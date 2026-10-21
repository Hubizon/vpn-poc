//! Layer 3 data plane: raw IP packets read from the TUN device are sent over
//! libp2p streams to the member that owns the destination virtual IP, and
//! packets arriving on streams are written back to the device.
//!
//! No extra encryption is needed here: libp2p streams are already encrypted
//! and bound to the peer's authenticated identity (Noise).
//!
//! Each member's virtual IP is derived from its peer ID inside `100.64.0.0/10`,
//! so peers agree on addresses without any coordination.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::Result;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::{PeerId, StreamProtocol};
use libp2p_stream::Control;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::{self, error::TrySendError};
use tun_rs::{AsyncDevice, DeviceBuilder};

const PROTOCOL: StreamProtocol = StreamProtocol::new("/vpn-poc/ip/1.0.0");
const NETWORK: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);
const PREFIX_LEN: u8 = 10;
const BROADCAST: Ipv4Addr = Ipv4Addr::new(100, 127, 255, 255);
/// Conservative: fits inside a relayed or QUIC path without fragmentation.
const MTU: u16 = 1280;
/// Packets queued per peer; more are dropped, like on a congested link.
const QUEUE: usize = 512;
const REOPEN_DELAY: Duration = Duration::from_secs(1);
const MAX_PACKET: usize = 2048;

type Routes = Arc<RwLock<HashMap<Ipv4Addr, PeerId>>>;

/// The virtual IP of a peer: a stable 22-bit hash of its ID inside `100.64.0.0/10`,
/// never the network or broadcast address.
pub fn virtual_ip(peer: &PeerId) -> Ipv4Addr {
    let hash = Sha256::digest(peer.to_bytes());
    let host = u32::from_be_bytes([0, hash[0] & 0x3f, hash[1], hash[2]]).clamp(1, 0x3F_FFFE);
    Ipv4Addr::from(u32::from(NETWORK) | host)
}

pub struct Vpn {
    pub ip: Ipv4Addr,
    routes: Routes,
}

impl Vpn {
    /// Creates the TUN device (needs administrator/root rights) and starts forwarding.
    pub fn start(local: PeerId, mut control: Control) -> Result<Self> {
        let ip = virtual_ip(&local);
        let device = Arc::new(DeviceBuilder::new().ipv4(ip, PREFIX_LEN, None).mtu(MTU).build_async()?);
        let routes = Routes::default();

        let incoming = control.accept(PROTOCOL)?;
        tokio::spawn(receive_loop(incoming, device.clone(), routes.clone()));
        tokio::spawn(send_loop(device, control, routes.clone()));
        Ok(Self { ip, routes })
    }

    /// Allows traffic to and from an authenticated member.
    /// Returns false if another member already uses the same virtual IP.
    pub fn add_peer(&self, peer: PeerId) -> bool {
        let mut routes = self.routes.write().unwrap();
        *routes.entry(virtual_ip(&peer)).or_insert(peer) == peer
    }
}

// ---------------------------------------------------------------------------
// TUN -> peers
// ---------------------------------------------------------------------------

async fn send_loop(device: Arc<AsyncDevice>, control: Control, routes: Routes) {
    let mut buf = vec![0u8; MAX_PACKET];
    let mut writers: HashMap<PeerId, mpsc::Sender<Vec<u8>>> = HashMap::new();
    loop {
        let len = match device.recv(&mut buf).await {
            Ok(len) => len,
            Err(e) => {
                tracing::error!("reading from the network adapter failed: {e}");
                return;
            }
        };
        let packet = &buf[..len];
        let Some(destination) = destination(packet) else { continue };
        for peer in targets(destination, &routes) {
            forward(&mut writers, &control, peer, packet);
        }
    }
}

/// Queues the packet for the peer's writer task, (re)starting it when needed.
fn forward(writers: &mut HashMap<PeerId, mpsc::Sender<Vec<u8>>>, control: &Control, peer: PeerId, packet: &[u8]) {
    let queue = writers.entry(peer).or_insert_with(|| spawn_writer(control.clone(), peer));
    if let Err(TrySendError::Closed(packet)) = queue.try_send(packet.to_vec()) {
        let queue = spawn_writer(control.clone(), peer);
        let _ = queue.try_send(packet);
        writers.insert(peer, queue);
    }
}

/// Owns the outgoing stream to one peer. Exits on any error; the next packet restarts it.
fn spawn_writer(mut control: Control, peer: PeerId) -> mpsc::Sender<Vec<u8>> {
    let (queue, mut packets) = mpsc::channel::<Vec<u8>>(QUEUE);
    tokio::spawn(async move {
        let mut stream = match control.open_stream(peer, PROTOCOL).await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::debug!("cannot open a stream to {peer}: {e}");
                // Packets arriving meanwhile pile up in the queue and are dropped.
                tokio::time::sleep(REOPEN_DELAY).await;
                return;
            }
        };
        while let Some(packet) = packets.recv().await {
            let frame = (packet.len() as u16).to_be_bytes();
            if stream.write_all(&frame).await.is_err()
                || stream.write_all(&packet).await.is_err()
                || stream.flush().await.is_err()
            {
                return;
            }
        }
    });
    queue
}

fn targets(destination: Ipv4Addr, routes: &Routes) -> Vec<PeerId> {
    let routes = routes.read().unwrap();
    if destination.is_multicast() || destination.is_broadcast() || destination == BROADCAST {
        routes.values().copied().collect()
    } else {
        routes.get(&destination).copied().into_iter().collect()
    }
}

// ---------------------------------------------------------------------------
// peers -> TUN
// ---------------------------------------------------------------------------

async fn receive_loop(mut incoming: libp2p_stream::IncomingStreams, device: Arc<AsyncDevice>, routes: Routes) {
    while let Some((peer, stream)) = incoming.next().await {
        let is_member = routes.read().unwrap().get(&virtual_ip(&peer)) == Some(&peer);
        if is_member {
            tokio::spawn(read_packets(peer, stream, device.clone()));
        } else {
            tracing::debug!("ignoring stream from non-member {peer}");
        }
    }
}

async fn read_packets(peer: PeerId, mut stream: libp2p::Stream, device: Arc<AsyncDevice>) {
    let expected_source = virtual_ip(&peer);
    let mut packet = vec![0u8; MAX_PACKET];
    loop {
        let mut frame = [0u8; 2];
        if stream.read_exact(&mut frame).await.is_err() {
            return;
        }
        let len = u16::from_be_bytes(frame) as usize;
        if len > MAX_PACKET || stream.read_exact(&mut packet[..len]).await.is_err() {
            return;
        }
        // A member may only send packets from its own virtual IP.
        if source(&packet[..len]) != Some(expected_source) {
            tracing::debug!("dropping packet from {peer} with a spoofed source address");
            continue;
        }
        if let Err(e) = device.send(&packet[..len]).await {
            tracing::debug!("writing to the network adapter failed: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// IPv4 header helpers
// ---------------------------------------------------------------------------

fn is_ipv4(packet: &[u8]) -> bool {
    packet.len() >= 20 && packet[0] >> 4 == 4
}

fn source(packet: &[u8]) -> Option<Ipv4Addr> {
    is_ipv4(packet).then(|| Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]))
}

fn destination(packet: &[u8]) -> Option<Ipv4Addr> {
    is_ipv4(packet).then(|| Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn virtual_ips_are_stable_and_inside_the_subnet() {
        for _ in 0..1000 {
            let peer = PeerId::random();
            let ip = virtual_ip(&peer);
            assert_eq!(ip, virtual_ip(&peer));
            assert_eq!(u32::from(ip) >> 22, u32::from(NETWORK) >> 22, "inside 100.64.0.0/10");
            assert_ne!(ip, NETWORK);
            assert_ne!(ip, BROADCAST);
        }
    }

    #[test]
    fn parses_ipv4_headers_and_ignores_the_rest() {
        let packet = ipv4_packet([100, 64, 0, 1], [100, 64, 0, 2]);
        assert_eq!(source(&packet), Some(Ipv4Addr::new(100, 64, 0, 1)));
        assert_eq!(destination(&packet), Some(Ipv4Addr::new(100, 64, 0, 2)));
        assert_eq!(destination(&packet[..10]), None, "truncated");
        let mut v6 = packet.clone();
        v6[0] = 0x60;
        assert_eq!(destination(&v6), None, "IPv6 is not carried");
    }

    #[test]
    fn broadcast_and_multicast_go_to_everyone_unicast_to_one_peer() {
        let (a, b) = (PeerId::random(), PeerId::random());
        let routes = Routes::default();
        for peer in [a, b] {
            routes.write().unwrap().insert(virtual_ip(&peer), peer);
        }
        assert_eq!(targets(BROADCAST, &routes).len(), 2);
        assert_eq!(targets(Ipv4Addr::new(255, 255, 255, 255), &routes).len(), 2);
        assert_eq!(targets(Ipv4Addr::new(224, 0, 0, 251), &routes).len(), 2);
        assert_eq!(targets(virtual_ip(&a), &routes), vec![a]);
        assert!(targets(Ipv4Addr::new(100, 64, 9, 9), &routes).is_empty());
    }
}
