//! Encrypted UDP transport for the mouse stream.
//!
//! The handshake is two datagrams: each side sends `[magic][x25519 public
//! key]`, both derive a ChaCha20-Poly1305 session from the peer's key and
//! the PSK, and every following packet is `[seq:u32][ciphertext]`. The
//! sequence number doubles as the AEAD nonce counter and lets the receiver
//! drop duplicates and late stragglers without waiting.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use crate::crypto::{Handshake, Role, Session};
use crate::proto;

/// Framing marker for handshake datagrams ("SCK1").
const MAGIC: [u8; 4] = [0x53, 0x43, 0x4b, 0x31];
/// How long the dialer keeps retrying its hello.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Poll granularity of the receive loop.
const READ_TIMEOUT: Duration = Duration::from_millis(1);

/// One end of an established mouse stream.
pub struct Channel {
    socket: UdpSocket,
    seq: u32,
    /// Highest sequence number seen, for straggler rejection.
    last_seen: u32,
    session: Session,
}

/// Dial the receiver: send our public key until the peer answers with its own.
pub fn initiator(socket: UdpSocket, psk: &[u8]) -> anyhow::Result<Channel> {
    let hs = Handshake::new();
    let mut hello = Vec::with_capacity(36);
    hello.extend_from_slice(&MAGIC);
    hello.extend_from_slice(&hs.public_bytes());

    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    let mut buf = [0u8; 2048];
    loop {
        socket.send(&hello)?;
        match socket.recv(&mut buf) {
            Ok(n) if n >= 36 && buf[..4] == MAGIC => {
                let peer_public: [u8; 32] = buf[4..36].try_into().expect("36 bytes checked");
                let session = hs.complete(peer_public, psk, Role::Initiator)?;
                socket.set_read_timeout(Some(READ_TIMEOUT))?;
                return Ok(Channel {
                    socket,
                    seq: 0,
                    last_seen: 0,
                    session,
                });
            }
            Ok(_) => continue, // stray datagram; ignore and retry
            Err(_) if Instant::now() >= deadline => {
                anyhow::bail!("no receiver answered the handshake")
            }
            Err(_) => continue, // recv timeout; resend the hello
        }
    }
}

/// Wait for a sender's hello and answer with our public key.
pub fn responder(socket: UdpSocket, psk: &[u8]) -> anyhow::Result<Channel> {
    let hs = Handshake::new();
    let mut hello = Vec::with_capacity(36);
    hello.extend_from_slice(&MAGIC);
    hello.extend_from_slice(&hs.public_bytes());

    // Blocking until the first hello arrives; the event loop sets its own
    // (short) read timeout afterwards.
    let mut buf = [0u8; 2048];
    let peer_public = loop {
        let (n, from) = socket.recv_from(&mut buf)?;
        if n >= 36 && buf[..4] == MAGIC {
            socket.send_to(&hello, from)?;
            break buf[4..36].try_into().expect("36 bytes checked");
        }
    };
    let session = hs.complete(peer_public, psk, Role::Responder)?;
    socket.set_read_timeout(Some(READ_TIMEOUT))?;
    Ok(Channel {
        socket,
        seq: 0,
        last_seen: 0,
        session,
    })
}

impl Channel {
    /// Send one batch of events (an empty batch is a keep-alive).
    pub fn send(&mut self, events: &[proto::MouseEvent]) -> anyhow::Result<()> {
        let body = proto::encode(events);
        let seq = self.seq;
        self.seq = seq.wrapping_add(1);
        let seq_bytes = seq.to_le_bytes();
        let ct = self.session.seal(seq as u64, &seq_bytes, &body);
        let mut out = Vec::with_capacity(4 + ct.len());
        out.extend_from_slice(&seq_bytes);
        out.extend_from_slice(&ct);
        self.socket.send(&out)?;
        Ok(())
    }

    /// Receive the next batch. `Ok(None)` means "timed out or dropped"
    /// (keep-alives decode to an empty batch).
    pub fn recv(&mut self, buf: &mut [u8]) -> anyhow::Result<Option<Vec<proto::MouseEvent>>> {
        let (n, _) = match self.socket.recv_from(buf) {
            Ok(v) => v,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Ok(None)
            }
            Err(e) => return Err(e.into()),
        };
        if n < 4 {
            return Ok(None);
        }
        let seq = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        // Duplicates and stragglers are simply dropped; seq 0 is exempt so a
        // wrap-around restart can't be mistaken for a straggler.
        if seq != 0 && seq <= self.last_seen {
            return Ok(None);
        }
        self.last_seen = seq;
        let Some(pt) = self.session.open(seq as u64, &buf[..4], &buf[4..n]).ok() else {
            return Ok(None); // failed authentication — not from our peer
        };
        Ok(proto::decode(&pt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::MouseEvent;

    /// Full stack over loopback: handshake, then an event round-trip.
    #[test]
    fn handshake_then_roundtrip() {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.connect(b.local_addr().unwrap()).unwrap();
        let psk = b"pairing-code";
        let dial = {
            let a = a.try_clone().unwrap();
            let psk = psk.to_vec();
            std::thread::spawn(move || initiator(a, &psk).unwrap())
        };
        let mut recv = responder(b, psk).unwrap();
        let mut send = dial.join().unwrap();

        send.send(&[MouseEvent::Move { dx: 3, dy: -4 }]).unwrap();
        let mut buf = [0u8; 2048];
        let events = loop {
            if let Some(e) = recv.recv(&mut buf).unwrap() {
                break e;
            }
        };
        assert_eq!(events, vec![MouseEvent::Move { dx: 3, dy: -4 }]);
    }

    /// A wrong PSK completes the handshake but fails every record.
    #[test]
    fn wrong_psk_drops_all_packets() {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.connect(b.local_addr().unwrap()).unwrap();
        let dial = {
            let a = a.try_clone().unwrap();
            std::thread::spawn(move || initiator(a, b"correct").unwrap())
        };
        let mut recv = responder(b, b"wrong").unwrap();
        let mut send = dial.join().unwrap();

        send.send(&[MouseEvent::Move { dx: 1, dy: 1 }]).unwrap();
        let mut buf = [0u8; 2048];
        let mut got_any = false;
        for _ in 0..50 {
            if recv.recv(&mut buf).unwrap().is_some() {
                got_any = true;
            }
        }
        assert!(!got_any, "mismatched PSK must not deliver events");
    }
}