# vpn-poc

Prototype of a serverless peer-to-peer layer 3 VPN (see RFC #0001), built on libp2p.
Peers behind home NATs find each other over the public **Amino DHT** and
connect through **circuit relays**, upgrading to direct links by **hole punching** (DCUtR).
Arbitrary IP traffic (ping, UDP/TCP, LAN game discovery via broadcast) then flows
through a virtual network adapter.

## How it works

1. A network is a secret *network code*. A one-way hash of it is the DHT key
   (a sha2-256 multihash, as in a CID); outsiders can't learn the code from it.
2. Each peer joins Amino as a client, reserves a slot on a public relay
   (kept renewed by libp2p) and publishes a provider record for the key,
   so the DHT maps `key -> peer ID + relay address`.
3. Peers look up the key's providers, dial them via their relays and prove
   knowledge of the code with an HMAC bound to both peer IDs (Noise already
   authenticates the IDs; the code is never sent).
4. DCUtR tries to replace relayed connections with direct ones.
5. **Data plane:** every member gets a virtual IP in `100.64.0.0/10`, derived from
   its peer ID. A TUN adapter hands raw IP packets to the app, which sends them
   over an (already encrypted) libp2p stream to the member owning the destination
   IP. Broadcast and multicast packets go to all members. Incoming packets whose
   source isn't the sender's own virtual IP are dropped.

No server of ours is involved: only the public IPFS bootstrap nodes, DHT peers and relays.

## Run

The adapter needs **administrator / root** rights.

Windows (PowerShell *as administrator*):
```
powershell -ExecutionPolicy Bypass -File scripts\get-wintun.ps1   # once: downloads wintun.dll
cargo run --release
```
Linux:
```
cargo build --release && sudo ./target/release/vpn-poc
```

The GUI opens at http://127.0.0.1:8080. "Create new network" and share the code,
or paste a code to join. Your virtual IP and each peer's are shown; use those
addresses in games, `ping`, SSH, etc.
Options: `--network <code>`, `--data-dir`, `--gui-port`, `--no-browser`.

Without administrator rights the app still connects and chats, and the GUI says
why the adapter is unavailable.

The identity key and network code are kept in `--data-dir` (default `vpn-poc-data`).
Cargo pins Rust 1.88 via `rust-toolchain.toml` (rustup installs it on demand).

## Limitations

- Packets travel over reliable streams (one per peer), so packet loss on a
  link shows up as latency spikes rather than drops. Fine for most LAN games,
  not ideal for fast-paced ones.
- IPv4 only inside the VPN. MTU is 1280.
- Windows may treat the new adapter as a "Public" network and block inbound
  connections; allow the game or set the network profile to Private.
- Needs cone-type NATs for hole punching; symmetric NATs stay on relays, which
  public relays throttle (about 2 min / 128 KiB per connection).
- Public relays may refuse reservations; the node tries other candidates.
- Only IPv4 relays are used. One network per run. Virtual IP collisions between
  members (about 1 in 4 million per pair) are detected and the later peer isn't routed.
