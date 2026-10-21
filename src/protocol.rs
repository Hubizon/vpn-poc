//! Network identity and the small wire protocols spoken between members.
//!
//! A network is defined by a shared secret (the "network code"). Two keys are
//! derived from it with distinct labels:
//!
//! * the **DHT key** – a sha2-256 multihash, i.e. the same thing a CID wraps.
//!   Every member announces itself as a provider of this key on the Amino DHT,
//!   so all members "have the same CID". Outsiders can't link the key back to
//!   the secret (one-way hash) and learn nothing else about the network.
//! * the **auth key** – used to HMAC the peer IDs of both ends of a connection,
//!   which proves knowledge of the secret without ever sending it. Peer IDs are
//!   already authenticated by libp2p's Noise handshake, so a proof can't be
//!   replayed by a different identity.

use hmac::{Hmac, Mac};
use libp2p::{kad::RecordKey, PeerId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AUTH_PROTOCOL: &str = "/vpn-poc/auth/1.0.0";
pub const CHAT_PROTOCOL: &str = "/vpn-poc/chat/1.0.0";

const ROLE_REQUEST: &[u8] = b"request";
const ROLE_RESPONSE: &[u8] = b"response";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// Empty when the request was rejected.
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub text: String,
}

/// Generates a fresh random network code.
pub fn new_network_code() -> String {
    let bytes: [u8; 16] = rand::random();
    format!("vpn-{}", hex::encode(bytes))
}

pub struct Network {
    code: String,
    dht_key: RecordKey,
    auth_key: [u8; 32],
}

impl Network {
    pub fn new(code: &str) -> Self {
        // Amino keys provider records by the multihash of a CID: 0x12 = sha2-256, 0x20 = length.
        let mut multihash = vec![0x12, 0x20];
        multihash.extend_from_slice(&derive("vpn-poc/dht/v1", code));
        Self {
            code: code.to_owned(),
            dht_key: RecordKey::new(&multihash),
            auth_key: derive("vpn-poc/auth/v1", code),
        }
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn dht_key(&self) -> RecordKey {
        self.dht_key.clone()
    }

    /// Proof sent by `from` when it opens an authentication request to `to`.
    pub fn request_proof(&self, from: &PeerId, to: &PeerId) -> Vec<u8> {
        self.mac(ROLE_REQUEST, from, to).finalize().into_bytes().to_vec()
    }

    pub fn verify_request(&self, proof: &[u8], from: &PeerId, to: &PeerId) -> bool {
        self.mac(ROLE_REQUEST, from, to).verify_slice(proof).is_ok()
    }

    /// Proof sent by `from` when answering a request of `to`.
    pub fn response_proof(&self, from: &PeerId, to: &PeerId) -> Vec<u8> {
        self.mac(ROLE_RESPONSE, from, to).finalize().into_bytes().to_vec()
    }

    pub fn verify_response(&self, proof: &[u8], from: &PeerId, to: &PeerId) -> bool {
        self.mac(ROLE_RESPONSE, from, to).verify_slice(proof).is_ok()
    }

    fn mac(&self, role: &[u8], from: &PeerId, to: &PeerId) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.auth_key).expect("HMAC accepts any key length");
        mac.update(role);
        mac.update(&from.to_bytes());
        mac.update(&to.to_bytes());
        mac
    }
}

fn derive(label: &str, code: &str) -> [u8; 32] {
    Sha256::new().chain_update(label).chain_update(code).finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_are_bound_to_network_role_and_peers() {
        let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
        let net = Network::new("secret-one");
        let other = Network::new("secret-two");

        let proof = net.request_proof(&a, &b);
        assert!(net.verify_request(&proof, &a, &b));
        assert!(!net.verify_request(&proof, &a, &c), "bound to the receiver");
        assert!(!net.verify_request(&proof, &c, &b), "bound to the sender");
        assert!(!other.verify_request(&proof, &a, &b), "bound to the secret");
        assert!(!net.verify_response(&proof, &a, &b), "requests are not responses");
    }

    #[test]
    fn same_code_gives_same_dht_key() {
        assert_eq!(Network::new("x").dht_key(), Network::new("x").dht_key());
        assert_ne!(Network::new("x").dht_key(), Network::new("y").dht_key());
    }
}
