//! Authenticated encryption for the mouse stream.
//!
//!  * **Key agreement:** ephemeral X25519 ECDH — fresh keypair per session.
//!  * **Authentication:** the user's pre-shared key (PSK / pairing code) is
//!    mixed into the HKDF *salt*. With a wrong PSK both sides derive different
//!    keys and every AEAD open fails — no PKI needed.
//!  * **Records:** ChaCha20-Poly1305 AEAD. Each direction has its own key and
//!    monotonic counter → nonce, so nonces never repeat under a key.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Which side of the exchange we are. Decides send/recv key orientation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The side that dials the other (`send`).
    Initiator,
    /// The side that listens (`recv`).
    Responder,
}

/// Errors from the crypto layer.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("decryption/authentication failed")]
    Decrypt,
    #[error("hkdf expand failed")]
    Kdf,
}

/// An in-progress handshake holding our ephemeral secret.
pub struct Handshake {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl Handshake {
    /// Generate a fresh ephemeral keypair for this session.
    pub fn new() -> Self {
        let secret = EphemeralSecret::random();
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Our public key to send to the peer (32 bytes).
    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Finish the handshake, deriving the directional [`Session`]. Consumes
    /// `self` (the ephemeral secret must be used exactly once).
    pub fn complete(
        self,
        peer_public: [u8; 32],
        psk: &[u8],
        role: Role,
    ) -> Result<Session, CryptoError> {
        let peer = PublicKey::from(peer_public);
        let shared = self.secret.diffie_hellman(&peer);

        // Bind both public keys into the HKDF info, ordered deterministically
        // so both sides compute the same value regardless of role.
        let ours = self.public.to_bytes();
        let theirs = peer_public;
        let (a, b) = if ours <= theirs { (ours, theirs) } else { (theirs, ours) };
        let mut info = Vec::with_capacity(8 + 64);
        info.extend_from_slice(b"sck-v1-kd");
        info.extend_from_slice(&a);
        info.extend_from_slice(&b);

        // HKDF-SHA256: salt = PSK (authentication), ikm = ECDH shared secret.
        let hk = Hkdf::<Sha256>::new(Some(psk), shared.as_bytes());
        let mut okm = [0u8; 64];
        hk.expand(&info, &mut okm).map_err(|_| CryptoError::Kdf)?;

        let (k_i2r, k_r2i) = okm.split_at(32);
        let (send_key, recv_key) = match role {
            Role::Initiator => (k_i2r, k_r2i),
            Role::Responder => (k_r2i, k_i2r),
        };
        Ok(Session {
            send: ChaCha20Poly1305::new(send_key.into()),
            recv: ChaCha20Poly1305::new(recv_key.into()),
        })
    }
}

impl Default for Handshake {
    fn default() -> Self {
        Self::new()
    }
}

/// A directional encrypted session.
pub struct Session {
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
}

impl Session {
    /// Encrypt `plaintext` for the peer. `counter` must be unique per
    /// direction (the packet sequence number is used).
    pub fn seal(&self, counter: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        self.send
            .encrypt(
                &nonce(counter),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("chacha20poly1305 encryption is infallible for valid input")
    }

    /// Decrypt a record produced by the peer at `counter`. Fails if the data
    /// was tampered with, the counter is wrong, or the PSK did not match.
    pub fn open(
        &self,
        counter: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.recv
            .decrypt(
                &nonce(counter),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Decrypt)
    }
}

/// Build a 96-bit nonce from a 64-bit counter (top 4 bytes zero).
fn nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    *Nonce::from_slice(&n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn established(psk_a: &[u8], psk_b: &[u8]) -> (Session, Session) {
        let a = Handshake::new();
        let b = Handshake::new();
        let a_pub = a.public_bytes();
        let b_pub = b.public_bytes();
        let sa = a.complete(b_pub, psk_a, Role::Initiator).unwrap();
        let sb = b.complete(a_pub, psk_b, Role::Responder).unwrap();
        (sa, sb)
    }

    #[test]
    fn roundtrip_both_directions() {
        let (alice, bob) = established(b"correct horse", b"correct horse");
        let ct = alice.seal(1, b"", b"mouse move");
        assert_eq!(bob.open(1, b"", &ct).unwrap(), b"mouse move");
        let ct2 = bob.seal(1, b"", b"release");
        assert_eq!(alice.open(1, b"", &ct2).unwrap(), b"release");
    }

    #[test]
    fn wrong_psk_cannot_decrypt() {
        let (alice, bob) = established(b"password-A", b"password-B");
        let ct = alice.seal(7, b"", b"secret");
        assert!(bob.open(7, b"", &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (alice, bob) = established(b"pw", b"pw");
        let mut ct = alice.seal(3, b"", b"click");
        ct[0] ^= 0xff;
        assert!(bob.open(3, b"", &ct).is_err());
    }

    #[test]
    fn wrong_counter_is_rejected() {
        let (alice, bob) = established(b"pw", b"pw");
        let ct = alice.seal(10, b"", b"scroll");
        assert!(bob.open(11, b"", &ct).is_err());
    }
}