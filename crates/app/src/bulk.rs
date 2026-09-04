//! Reliable "bulk" channel (TCP) for clipboard sync and file transfer.
//!
//! Frames are length-prefixed: `u32` big-endian byte count followed by the
//! postcard-encoded [`BulkMsg`]. Ordering and delivery matter here more than
//! microseconds, so TCP is the right tool (unlike the input path).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use shareclick_protocol::crypto::{Handshake, Role, Session};
use shareclick_protocol::{BulkMsg, PROTOCOL_VERSION};

/// Max frame size we will accept, to avoid unbounded allocations from a peer.
const MAX_FRAME: u32 = 64 * 1024 * 1024; // 64 MiB

/// A framed connection over a TCP stream, optionally ChaCha20-Poly1305 sealed.
///
/// When encrypted, the counter used for each record's nonce is *implicit*: TCP
/// delivers frames in order, so both peers keep in-sync send/recv counters and
/// never need to transmit them. A reader handle only advances `recv_ctr`; a
/// writer handle only advances `send_ctr`.
pub struct BulkConn {
    stream: TcpStream,
    cipher: Option<Arc<Session>>,
    send_ctr: u64,
    recv_ctr: u64,
}

impl BulkConn {
    pub fn new(stream: TcpStream) -> std::io::Result<Self> {
        stream.set_nodelay(true)?; // clipboard/file latency: don't Nagle-buffer
        Ok(Self {
            stream,
            cipher: None,
            send_ctr: 0,
            recv_ctr: 0,
        })
    }

    /// Perform an X25519 + PSK handshake over the raw stream, returning an
    /// encrypted bulk connection plus the derived **input-channel** session for
    /// the UDP path. `role` must be [`Role::Initiator`] on the connecting side
    /// and [`Role::Responder`] on the accepting side.
    pub fn handshake(stream: TcpStream, psk: &[u8], role: Role) -> anyhow::Result<(Self, Session)> {
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut stream = stream;
        let hs = Handshake::new();
        let ours = hs.public_bytes();
        // Exchange 32-byte public keys in the clear (safe for ECDH).
        stream.write_all(&ours)?;
        stream.flush()?;
        let mut theirs = [0u8; 32];
        stream.read_exact(&mut theirs)?;
        let (input, bulk) = hs
            .complete_bundle(theirs, psk, role)
            .map_err(|e| anyhow::anyhow!("handshake failed: {e}"))?;
        let mut conn = Self {
            stream,
            cipher: Some(Arc::new(bulk)),
            send_ctr: 0,
            recv_ctr: 0,
        };

        // Key derivation alone cannot prove that both peers used the same PSK:
        // with a wrong code both sides still derive keys, just different ones.
        // Exchange a first encrypted record and validate it before reporting an
        // authenticated connection. This also rejects incompatible protocols
        // before input capture starts.
        conn.send(&BulkMsg::Welcome {
            version: PROTOCOL_VERSION,
            name: String::new(),
        })?;
        match conn.recv()? {
            BulkMsg::Welcome { version, .. } if version == PROTOCOL_VERSION => {}
            BulkMsg::Welcome { version, .. } => anyhow::bail!(
                "incompatible protocol version: peer uses {version}, this build uses {PROTOCOL_VERSION}"
            ),
            _ => anyhow::bail!("invalid encrypted handshake confirmation"),
        }
        conn.stream.set_read_timeout(None)?;
        conn.stream.set_write_timeout(None)?;
        Ok((conn, input))
    }

    /// Clone into an independent handle sharing the same cipher. Each clone is
    /// used for a single direction (all reads or all writes), preserving the
    /// counters already consumed by the encrypted handshake confirmation.
    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            stream: self.stream.try_clone()?,
            cipher: self.cipher.clone(),
            send_ctr: self.send_ctr,
            recv_ctr: self.recv_ctr,
        })
    }

    /// Clone only the underlying socket so a session owner can shut it down
    /// and unblock the bulk reader when the UDP input side has failed.
    pub fn shutdown_handle(&self) -> std::io::Result<TcpStream> {
        self.stream.try_clone()
    }

    pub fn send(&mut self, msg: &BulkMsg) -> anyhow::Result<()> {
        let body = msg.encode()?;
        let payload = match &self.cipher {
            Some(session) => {
                let ct = session.seal(self.send_ctr, &[], &body);
                self.send_ctr += 1;
                ct
            }
            None => body,
        };
        let len = payload.len() as u32;
        self.stream.write_all(&len.to_be_bytes())?;
        self.stream.write_all(&payload)?;
        self.stream.flush()?;
        Ok(())
    }

    pub fn recv(&mut self) -> anyhow::Result<BulkMsg> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_FRAME {
            anyhow::bail!("bulk frame too large: {len} bytes");
        }
        let mut buf = vec![0u8; len as usize];
        self.stream.read_exact(&mut buf)?;
        match &self.cipher {
            Some(session) => {
                let pt = session
                    .open(self.recv_ctr, &[], &buf)
                    .map_err(|e| anyhow::anyhow!("bulk decrypt failed: {e}"))?;
                self.recv_ctr += 1;
                Ok(BulkMsg::decode(&pt)?)
            }
            None => Ok(BulkMsg::decode(&buf)?),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shareclick_protocol::ClipboardData;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn bulk_frames_roundtrip_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut conn = BulkConn::new(stream).unwrap();
            // Echo back three framed messages.
            for _ in 0..3 {
                let msg = conn.recv().unwrap();
                conn.send(&msg).unwrap();
            }
        });

        let mut client = BulkConn::new(TcpStream::connect(addr).unwrap()).unwrap();
        let msgs = vec![
            BulkMsg::Clipboard(ClipboardData::Text("hello world".into())),
            BulkMsg::Heartbeat,
            BulkMsg::FileBegin {
                id: 7,
                name: "a.txt".into(),
                size: 12,
            },
        ];
        for m in &msgs {
            client.send(m).unwrap();
            assert_eq!(&client.recv().unwrap(), m);
        }
        server.join().unwrap();
    }

    #[test]
    fn encrypted_handshake_and_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let psk = b"a-sufficiently-long-passphrase";

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (mut conn, _input) = BulkConn::handshake(stream, psk, Role::Responder).unwrap();
            for _ in 0..3 {
                let msg = conn.recv().unwrap();
                conn.send(&msg).unwrap();
            }
        });

        let (mut client, _input) =
            BulkConn::handshake(TcpStream::connect(addr).unwrap(), psk, Role::Initiator).unwrap();
        let msgs = vec![
            BulkMsg::Clipboard(ClipboardData::Text("encrypted!".into())),
            BulkMsg::Heartbeat,
            BulkMsg::FileChunk {
                id: 1,
                offset: 0,
                data: vec![1, 2, 3, 4],
            },
        ];
        for m in &msgs {
            client.send(m).unwrap();
            assert_eq!(&client.recv().unwrap(), m);
        }
        server.join().unwrap();
    }

    #[test]
    fn encrypted_handshake_rejects_a_different_pairing_code() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            BulkConn::handshake(stream, b"server-pairing-code", Role::Responder).is_err()
        });

        let client = BulkConn::handshake(
            TcpStream::connect(addr).unwrap(),
            b"different-client-code",
            Role::Initiator,
        );
        assert!(client.is_err());
        assert!(server.join().unwrap());
    }
}
