//! The libp2p node: Amino DHT discovery, relay reservation, hole punching and
//! member authentication.
//!
//! Flow for a peer behind a home NAT:
//! 1. Join the public Amino DHT (client mode) via the IPFS bootstrap nodes.
//! 2. Pick a public peer that offers circuit relay v2 and reserve a slot on it.
//!    The libp2p relay client keeps the reservation renewed.
//! 3. Announce the relayed address as external and publish a DHT provider record
//!    for the network's key, so the record maps `key -> (our peer id, relay address)`.
//! 4. Look up providers of the key, dial each through its relay, and prove
//!    knowledge of the network secret (see [`crate::protocol`]).
//! 5. DCUtR upgrades relayed connections to direct ones via hole punching.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    core::{multiaddr::Protocol, transport::ListenerId},
    dcutr, identify,
    identity::Keypair,
    kad::{self, store::MemoryStore, GetProvidersOk, QueryResult},
    noise, ping, relay,
    request_response::{self, ProtocolSupport},
    swarm::{
        dial_opts::{DialOpts, PeerCondition},
        NetworkBehaviour, SwarmEvent,
    },
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm,
};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::protocol::*;
use crate::vpn::{virtual_ip, Vpn};

const BOOTSTRAP_ADDR: &str = "/dnsaddr/bootstrap.libp2p.io";
const BOOTSTRAP_PEERS: [&str; 4] = [
    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];
const AMINO_PROTOCOL: &str = "/ipfs/kad/1.0.0";
const RELAY_HOP_PROTOCOL: &str = "/libp2p/circuit/relay/0.2.0/hop";

const TICK: Duration = Duration::from_secs(15);
/// Re-publish our provider record and refresh the routing table every this many ticks.
const REFRESH_EVERY_TICKS: u32 = 20;
const MAX_RELAY_CANDIDATES: usize = 32;
const MAX_LOG_LINES: usize = 200;

// ---------------------------------------------------------------------------
// State shared with the GUI
// ---------------------------------------------------------------------------

#[derive(Default, Clone, Serialize)]
pub struct Snapshot {
    pub peer_id: String,
    pub network_code: Option<String>,
    pub relay: Option<String>,
    /// Our address inside the VPN, if the network adapter is up.
    pub virtual_ip: Option<String>,
    /// Why the network adapter could not be created.
    pub vpn_error: Option<String>,
    pub dht_peers: usize,
    pub peers: Vec<PeerView>,
    pub chat: Vec<ChatLine>,
    pub log: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct PeerView {
    pub id: String,
    pub ip: String,
    pub authenticated: bool,
    /// "direct", "relayed" or "offline".
    pub connection: &'static str,
    pub rtt_ms: Option<u64>,
}

#[derive(Clone, Serialize)]
pub struct ChatLine {
    pub peer: String,
    pub incoming: bool,
    pub text: String,
}

pub type Shared = Arc<Mutex<Snapshot>>;

pub enum Command {
    Join(String),
    Send { peer: PeerId, text: String },
}

// ---------------------------------------------------------------------------
// Behaviour
// ---------------------------------------------------------------------------

#[derive(NetworkBehaviour)]
struct Behaviour {
    kad: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    relay: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    ping: ping::Behaviour,
    auth: request_response::cbor::Behaviour<AuthRequest, AuthResponse>,
    chat: request_response::cbor::Behaviour<ChatMessage, ()>,
    stream: libp2p_stream::Behaviour,
}

fn build_swarm(keypair: Keypair) -> Result<Swarm<Behaviour>> {
    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_dns()?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay| {
            let local = key.public().to_peer_id();

            // Amino is the public IPFS DHT. Behind NAT we only ever act as a client.
            let kad_config = kad::Config::new(StreamProtocol::new(AMINO_PROTOCOL));
            let mut kad = kad::Behaviour::with_config(local, MemoryStore::new(local), kad_config);
            kad.set_mode(Some(kad::Mode::Client));

            let rr_config = request_response::Config::default();
            Behaviour {
                kad,
                identify: identify::Behaviour::new(identify::Config::new("/vpn-poc/1.0.0".into(), key.public())),
                relay,
                dcutr: dcutr::Behaviour::new(local),
                ping: ping::Behaviour::default(),
                auth: request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(AUTH_PROTOCOL), ProtocolSupport::Full)],
                    rr_config.clone(),
                ),
                chat: request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(CHAT_PROTOCOL), ProtocolSupport::Full)],
                    rr_config,
                ),
                stream: libp2p_stream::Behaviour::new(),
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();
    Ok(swarm)
}

fn load_or_create_identity(data_dir: &Path) -> Result<Keypair> {
    let path = data_dir.join("identity.key");
    if path.exists() {
        return Ok(Keypair::from_protobuf_encoding(&fs::read(path)?)?);
    }
    let keypair = Keypair::generate_ed25519();
    fs::write(path, keypair.to_protobuf_encoding()?)?;
    Ok(keypair)
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Member {
    authenticated: bool,
    auth_in_flight: bool,
    rtt: Option<Duration>,
}

struct RelayState {
    peer: PeerId,
    listener: ListenerId,
    address: Option<Multiaddr>,
}

#[derive(Default)]
struct Connections {
    direct: u32,
    relayed: u32,
}

pub struct Node {
    swarm: Swarm<Behaviour>,
    local: PeerId,
    shared: Shared,
    commands: mpsc::UnboundedReceiver<Command>,
    network_file: PathBuf,

    network: Option<Network>,
    vpn: Option<Vpn>,
    /// Peers announced as providers of our network key, or that proved membership.
    members: BTreeMap<PeerId, Member>,
    connections: HashMap<PeerId, Connections>,

    relay_candidates: VecDeque<(PeerId, Multiaddr)>,
    relay_tried: HashSet<PeerId>,
    /// The relay we are currently using and the `.../p2p-circuit` address it gave us.
    relay: Option<RelayState>,
    ticks: u32,
}

impl Node {
    pub fn new(data_dir: &Path, shared: Shared, commands: mpsc::UnboundedReceiver<Command>) -> Result<Self> {
        fs::create_dir_all(data_dir)?;
        let mut swarm = build_swarm(load_or_create_identity(data_dir)?)?;
        let local = *swarm.local_peer_id();

        // Local listeners are needed for hole punching, not for reachability.
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;

        for peer in BOOTSTRAP_PEERS {
            swarm.behaviour_mut().kad.add_address(&peer.parse()?, BOOTSTRAP_ADDR.parse()?);
        }
        swarm.behaviour_mut().kad.bootstrap()?;

        // Creating the adapter needs administrator/root rights; without it we still connect and chat.
        let vpn = match Vpn::start(local, swarm.behaviour().stream.new_control()) {
            Ok(vpn) => Some(vpn),
            Err(e) => {
                let message = format!("network adapter unavailable (run as administrator/root; on Windows wintun.dll must be next to the executable): {e}");
                tracing::warn!("{message}");
                shared.lock().unwrap().vpn_error = Some(message);
                None
            }
        };

        {
            let mut snapshot = shared.lock().unwrap();
            snapshot.peer_id = local.to_string();
            snapshot.virtual_ip = vpn.as_ref().map(|v| v.ip.to_string());
        }
        Ok(Self {
            swarm,
            local,
            shared,
            commands,
            network_file: data_dir.join("network.txt"),
            network: None,
            vpn,
            members: BTreeMap::new(),
            connections: HashMap::new(),
            relay_candidates: VecDeque::new(),
            relay_tried: HashSet::new(),
            relay: None,
            ticks: 0,
        })
    }

    /// Rejoins the network saved by a previous run, if any.
    pub fn restore_network(&mut self) {
        if let Ok(code) = fs::read_to_string(&self.network_file) {
            self.join(code.trim());
        }
    }

    pub fn join(&mut self, code: &str) {
        if self.network.is_some() {
            self.log("already joined a network; restart with a fresh data dir to switch");
            return;
        }
        if let Err(e) = fs::write(&self.network_file, code) {
            self.log(format!("could not save network code: {e}"));
        }
        let network = Network::new(code);
        self.shared.lock().unwrap().network_code = Some(network.code().to_owned());
        self.network = Some(network);
        self.log("joined network, looking for peers");
        self.announce();
        self.discover();
    }

    pub async fn run(mut self) {
        let mut tick = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => self.on_swarm_event(event),
                Some(command) = self.commands.recv() => self.on_command(command),
                _ = tick.tick() => self.on_tick(),
            }
            self.publish();
        }
    }

    // -- periodic work ------------------------------------------------------

    fn on_tick(&mut self) {
        self.ticks += 1;
        if self.relay.is_none() {
            self.use_next_relay();
        }
        if self.ticks % REFRESH_EVERY_TICKS == 0 {
            let kad = &mut self.swarm.behaviour_mut().kad;
            let _ = kad.bootstrap();
            self.announce();
        }
        self.discover();
    }

    /// Publishes the provider record: our peer ID plus our relayed address.
    fn announce(&mut self) {
        let (Some(network), Some(RelayState { address: Some(_), .. })) = (&self.network, &self.relay) else {
            return; // Nothing reachable to announce yet.
        };
        let key = network.dht_key();
        if let Err(e) = self.swarm.behaviour_mut().kad.start_providing(key) {
            self.log(format!("could not announce on the DHT: {e}"));
        }
    }

    /// Looks up other providers of our network key; found peers are dialed in `on_kad_event`.
    fn discover(&mut self) {
        if let Some(network) = &self.network {
            let key = network.dht_key();
            self.swarm.behaviour_mut().kad.get_providers(key);
        }
    }

    // -- relay handling -----------------------------------------------------

    fn consider_relay(&mut self, peer: PeerId, addrs: &[Multiaddr]) {
        let known = self.relay_candidates.iter().any(|(p, _)| *p == peer);
        if known || self.relay_tried.contains(&peer) || self.relay_candidates.len() >= MAX_RELAY_CANDIDATES {
            return;
        }
        if let Some(addr) = addrs.iter().find_map(public_dialable) {
            self.relay_candidates.push_back((peer, addr));
            if self.relay.is_none() {
                self.use_next_relay();
            }
        }
    }

    fn use_next_relay(&mut self) {
        if self.relay.is_some() {
            return;
        }
        let Some((peer, addr)) = self.relay_candidates.pop_front() else {
            // Out of candidates: walk the DHT, which connects us to (and identifies) more peers.
            self.relay_tried.clear();
            self.swarm.behaviour_mut().kad.get_closest_peers(PeerId::random());
            return;
        };
        self.relay_tried.insert(peer);
        let circuit = addr.with(Protocol::P2p(peer)).with(Protocol::P2pCircuit);
        match self.swarm.listen_on(circuit) {
            Ok(listener) => {
                self.log(format!("reserving a slot on relay {peer}"));
                self.relay = Some(RelayState { peer, listener, address: None });
            }
            Err(e) => self.log(format!("cannot use relay {peer}: {e}")),
        }
    }

    fn on_relay_address(&mut self, address: Multiaddr) {
        let address = address.clone().with_p2p(self.local).unwrap_or(address);
        if let Some(relay) = &mut self.relay {
            relay.address = Some(address.clone());
        }
        self.swarm.add_external_address(address.clone());
        self.log(format!("reachable through relay at {address}"));
        self.announce();
    }

    fn on_relay_lost(&mut self) {
        if let Some(RelayState { peer, address, .. }) = self.relay.take() {
            self.log(format!("lost relay {peer}, picking another"));
            if let Some(address) = address {
                self.swarm.remove_external_address(&address);
            }
        }
        self.use_next_relay();
    }

    // -- events -------------------------------------------------------------

    fn on_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } if is_circuit(&address) => self.on_relay_address(address),
            SwarmEvent::ListenerClosed { listener_id, reason, .. } if self.is_relay_listener(listener_id) => {
                tracing::debug!("relay listener closed: {reason:?}");
                self.on_relay_lost();
            }
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                let conns = self.connections.entry(peer_id).or_default();
                if endpoint.is_relayed() {
                    conns.relayed += 1;
                } else {
                    conns.direct += 1;
                }
                self.authenticate_if_needed(peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id, endpoint, .. } => {
                if let Some(conns) = self.connections.get_mut(&peer_id) {
                    let count = if endpoint.is_relayed() { &mut conns.relayed } else { &mut conns.direct };
                    *count = count.saturating_sub(1);
                    if conns.direct + conns.relayed == 0 {
                        self.connections.remove(&peer_id);
                    }
                }
            }
            SwarmEvent::Behaviour(event) => self.on_behaviour_event(event),
            other => tracing::debug!("{other:?}"),
        }
    }

    fn on_behaviour_event(&mut self, event: BehaviourEvent) {
        match event {
            BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { result, .. }) => self.on_query_result(result),
            BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                if info.protocols.iter().any(|p| p.as_ref() == RELAY_HOP_PROTOCOL) {
                    self.consider_relay(peer_id, &info.listen_addrs);
                }
            }
            BehaviourEvent::Dcutr(dcutr::Event { remote_peer_id, result }) => match result {
                Ok(_) => self.log(format!("hole punched a direct connection to {remote_peer_id}")),
                Err(e) => self.log(format!("hole punching to {remote_peer_id} failed: {e}")),
            },
            BehaviourEvent::Ping(ping::Event { peer, result: Ok(rtt), .. }) => {
                if let Some(member) = self.members.get_mut(&peer) {
                    member.rtt = Some(rtt);
                }
            }
            BehaviourEvent::Auth(event) => self.on_auth_event(event),
            BehaviourEvent::Chat(event) => self.on_chat_event(event),
            _ => {}
        }
    }

    fn on_query_result(&mut self, result: QueryResult) {
        match result {
            QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders { providers, .. })) => {
                let local = self.local;
                for peer in providers.into_iter().filter(|p| *p != local) {
                    self.members.entry(peer).or_default();
                    // The DHT lookup is still running, so kad knows the providers' (relayed)
                    // addresses and the swarm can dial by peer ID alone.
                    let dial = DialOpts::peer_id(peer).condition(PeerCondition::DisconnectedAndNotDialing).build();
                    if !self.connections.contains_key(&peer) {
                        if let Err(e) = self.swarm.dial(dial) {
                            tracing::debug!("dial {peer}: {e}");
                        }
                    }
                    self.authenticate_if_needed(peer);
                }
            }
            QueryResult::StartProviding(Err(e)) => self.log(format!("announcing on the DHT failed: {e}")),
            QueryResult::StartProviding(Ok(_)) => tracing::debug!("announced on the DHT"),
            _ => {}
        }
    }

    // -- authentication -----------------------------------------------------

    fn authenticate_if_needed(&mut self, peer: PeerId) {
        let Some(network) = &self.network else { return };
        let Some(member) = self.members.get_mut(&peer) else { return };
        if member.authenticated || member.auth_in_flight || !self.connections.contains_key(&peer) {
            return;
        }
        member.auth_in_flight = true;
        let proof = network.request_proof(&self.local, &peer);
        self.swarm.behaviour_mut().auth.send_request(&peer, AuthRequest { proof });
    }

    fn mark_authenticated(&mut self, peer: PeerId) {
        let member = self.members.entry(peer).or_default();
        member.auth_in_flight = false;
        if !member.authenticated {
            member.authenticated = true;
            self.log(format!("peer {peer} proved membership"));
            if self.vpn.as_ref().is_some_and(|vpn| !vpn.add_peer(peer)) {
                self.log(format!("peer {peer} has the same virtual IP as another member and is not routed"));
            }
        }
    }

    fn on_auth_event(&mut self, event: request_response::Event<AuthRequest, AuthResponse>) {
        use request_response::{Event, Message};
        match event {
            Event::Message { peer, message: Message::Request { request, channel, .. } } => {
                let Some(network) = &self.network else {
                    let _ = self.swarm.behaviour_mut().auth.send_response(channel, AuthResponse { proof: vec![] });
                    return;
                };
                let valid = network.verify_request(&request.proof, &peer, &self.local);
                let proof = if valid { network.response_proof(&self.local, &peer) } else { vec![] };
                let _ = self.swarm.behaviour_mut().auth.send_response(channel, AuthResponse { proof });
                if valid {
                    self.mark_authenticated(peer);
                }
            }
            Event::Message { peer, message: Message::Response { response, .. } } => {
                let valid = self
                    .network
                    .as_ref()
                    .is_some_and(|n| n.verify_response(&response.proof, &peer, &self.local));
                if valid {
                    self.mark_authenticated(peer);
                } else {
                    // Probably a different network that happens to share a provider record.
                    self.members.remove(&peer);
                    tracing::debug!("peer {peer} rejected our proof");
                }
            }
            Event::OutboundFailure { peer, error, .. } => {
                tracing::debug!("auth request to {peer} failed: {error}");
                if let Some(member) = self.members.get_mut(&peer) {
                    member.auth_in_flight = false;
                }
            }
            _ => {}
        }
    }

    // -- chat ---------------------------------------------------------------

    fn on_chat_event(&mut self, event: request_response::Event<ChatMessage, ()>) {
        use request_response::{Event, Message};
        if let Event::Message { peer, message: Message::Request { request, channel, .. } } = event {
            let _ = self.swarm.behaviour_mut().chat.send_response(channel, ());
            if self.members.get(&peer).is_some_and(|m| m.authenticated) {
                self.push_chat(peer, true, request.text);
            }
        }
    }

    fn push_chat(&self, peer: PeerId, incoming: bool, text: String) {
        self.shared.lock().unwrap().chat.push(ChatLine { peer: peer.to_string(), incoming, text });
    }

    // -- commands & bookkeeping ---------------------------------------------

    fn on_command(&mut self, command: Command) {
        match command {
            Command::Join(code) => self.join(&code),
            Command::Send { peer, text } => {
                let reachable = self.members.get(&peer).is_some_and(|m| m.authenticated)
                    && self.connections.contains_key(&peer);
                if reachable {
                    self.swarm.behaviour_mut().chat.send_request(&peer, ChatMessage { text: text.clone() });
                    self.push_chat(peer, false, text);
                } else {
                    self.log(format!("peer {peer} is not connected"));
                }
            }
        }
    }

    fn log(&self, message: impl Into<String>) {
        let message = message.into();
        tracing::info!("{message}");
        let mut shared = self.shared.lock().unwrap();
        shared.log.push(message);
        let excess = shared.log.len().saturating_sub(MAX_LOG_LINES);
        shared.log.drain(..excess);
    }

    /// Copies the node state into the snapshot the GUI reads.
    fn publish(&mut self) {
        let peers = self
            .members
            .iter()
            .map(|(id, member)| {
                let connection = match self.connections.get(id) {
                    Some(c) if c.direct > 0 => "direct",
                    Some(_) => "relayed",
                    None => "offline",
                };
                PeerView {
                    id: id.to_string(),
                    ip: virtual_ip(id).to_string(),
                    authenticated: member.authenticated,
                    connection,
                    rtt_ms: member.rtt.map(|d| d.as_millis() as u64),
                }
            })
            .collect();
        let dht_peers = self.swarm.behaviour_mut().kad.kbuckets().map(|b| b.num_entries()).sum();
        let relay = self.relay.as_ref().and_then(|r| r.address.as_ref()).map(|a| a.to_string());

        let mut shared = self.shared.lock().unwrap();
        shared.peers = peers;
        shared.dht_peers = dht_peers;
        shared.relay = relay;
    }
}

impl Node {
    fn is_relay_listener(&self, id: ListenerId) -> bool {
        self.relay.as_ref().is_some_and(|r| r.listener == id)
    }
}

fn is_circuit(address: &Multiaddr) -> bool {
    address.iter().any(|p| matches!(p, Protocol::P2pCircuit))
}

/// Returns the plain public IPv4 TCP or QUIC address, without any `/p2p` suffix.
fn public_dialable(address: &Multiaddr) -> Option<Multiaddr> {
    let parts: Vec<Protocol> = address.iter().filter(|p| !matches!(p, Protocol::P2p(_))).collect();
    let ip = match parts.as_slice() {
        [Protocol::Ip4(ip), Protocol::Tcp(_)] => ip,
        [Protocol::Ip4(ip), Protocol::Udp(_), Protocol::QuicV1] => ip,
        _ => return None,
    };
    let private = ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation();
    (!private).then(|| parts.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_plain_addresses_are_relay_candidates() {
        let ok = |s: &str| public_dialable(&s.parse().unwrap()).is_some();
        assert!(ok("/ip4/8.8.8.8/tcp/4001"));
        assert!(ok("/ip4/8.8.8.8/udp/4001/quic-v1"));
        assert!(ok("/ip4/8.8.8.8/tcp/4001/p2p/12D3KooWGzxzKZYveHXtpG6AsrUJBcWxHBFS2HsEoGTxrMLvKXtf"));
        assert!(!ok("/ip4/192.168.1.2/tcp/4001"));
        assert!(!ok("/ip4/127.0.0.1/tcp/4001"));
        assert!(!ok("/ip4/8.8.8.8/tcp/4001/ws"));
        assert!(!ok("/ip6/2001:db8::1/tcp/4001"));
    }
}
