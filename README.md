# shareclick (minimal)

Control one computer's mouse from another over the LAN — nothing else.

One machine *sends* its physical mouse, the other *receives* and injects it as
real input. Mouse-only, one-way, no config file, no pairing UI.

```
cargo build --release
```

## Usage

On the machine whose mouse you want to **use remotely** (the receiver):

```sh
./target/release/shareclick recv            # listens on UDP 24800
./target/release/shareclick recv --port 9000 --psk my-secret
```

On the machine with the **physical mouse** (the sender):

```sh
./target/release/shareclick send 192.168.1.20
./target/release/shareclick send 192.168.1.20:9000 --psk my-secret
```

While connected, the sender's mouse still works locally until you toggle
control:

* **F12** toggles control (Windows/Linux)
* **hold both Shift keys** toggles control (works everywhere — the escape hatch)

While control is on, all of the sender's input goes to the receiver and is
swallowed locally.

Both sides must use the same `--psk` (default `shareclick`). Traffic is
encrypted with X25519 + ChaCha20-Poly1305; with a mismatched PSK nothing gets
through.

## Notes

* macOS: **both** machines need Accessibility permission for the terminal/app
  (capture needs it on the sender, injection needs it on the receiver).
* The stream is UDP with sequence numbers — dropped packets are skipped, not
  queued, to keep latency low.
* An idle sender sends a keep-alive every 500 ms; the receiver exits if the
  sender is silent for 15 s.

## Why this branch exists

This is the `minimal` branch: the full ShareClick (screen-edge hand-off,
keyboard, clipboard, file transfer, mDNS pairing, tray/GUI, background
service) stripped down to the smallest useful mouse-forwarding core. See
`main` for the complete product.