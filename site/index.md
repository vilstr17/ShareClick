# ShareClick — share one keyboard & mouse across Mac and Windows

> Free, open-source software KVM. One keyboard, mouse, clipboard and files
> across a Mac and a Windows PC over your LAN. Encrypted, low-latency, no cloud.

ShareClick is a free, open-source **software KVM**. It lets one keyboard and mouse
control both a Mac and a Windows PC over your local network, with clipboard (text
and images) and file sharing built in. Every channel is end-to-end encrypted
(X25519 key exchange + ChaCha20-Poly1305) and it runs LAN-only — no hardware, no
cloud, no account. It is a free alternative to Synergy, ShareMouse, Barrier and
Input Leap, with a low-latency UDP input path (~6 µs measured loopback transport overhead).

- **Price:** Free — open source (MIT / Apache-2.0), unlimited machines
- **Platforms:** macOS and Windows
- **Download:** https://github.com/phun333/ShareClick/releases
- **Source:** https://github.com/phun333/ShareClick

## Development status

ShareClick is under active development and may not work reliably on every macOS
and Windows setup. If you try it, please [report bugs](https://github.com/phun333/ShareClick/issues/new?template=bug_report.yml),
[suggest improvements](https://github.com/phun333/ShareClick/issues/new?template=feature_request.yml), or
[contribute a fix](https://github.com/phun333/ShareClick/blob/main/CONTRIBUTING.md).

## Features

- Share one keyboard and mouse across Mac and Windows
- Clipboard sync (text and images)
- File transfer over the LAN
- End-to-end encryption (X25519 + ChaCha20-Poly1305), authenticated by a shared passphrase
- Automatic screen-edge switching — push the cursor to the border to switch machines (plus a hotkey)
- mDNS zero-config discovery — no IP addresses to type
- Low-latency input design: ~6 µs measured loopback transport overhead on a UDP path

## FAQ

**What is ShareClick?**
ShareClick is a free, open-source software KVM for controlling a Mac and a
Windows PC with one keyboard and mouse over your local network. It is under
active development, so reliability may vary by setup.

**Is ShareClick free?**
Yes. It is completely free and open source (MIT / Apache-2.0). No account, no
subscription, no cloud.

**Does it share a mouse and keyboard between Mac and Windows?**
That is what ShareClick is built to do. Current builds let one keyboard and
mouse control a Mac and a Windows PC over the local network, but compatibility
may vary during development.

**Is ShareClick a free alternative to Synergy and ShareMouse?**
ShareClick is being developed as a free, open-source alternative with input
sharing, clipboard sync, file transfer, and a focus on lower input lag.

**Does it sync the clipboard and transfer files?**
Current builds include clipboard sync for text and images plus encrypted file
transfer. These features may not work reliably on every setup yet.

**Is it secure and does it need the internet?**
It runs on your local network only — no cloud. Every channel is end-to-end
encrypted with X25519 key exchange and ChaCha20-Poly1305, authenticated by a
shared passphrase.

## More

- [Setup guide](https://phun333.github.io/ShareClick/how-to-share-mouse-keyboard-mac-windows.md)
- [ShareClick vs Synergy](https://phun333.github.io/ShareClick/vs-synergy.md)
- [ShareClick vs ShareMouse](https://phun333.github.io/ShareClick/vs-sharemouse.md)
- [ShareClick vs Barrier](https://phun333.github.io/ShareClick/vs-barrier.md)
- [Synergy alternatives compared](https://phun333.github.io/ShareClick/synergy-alternatives.md)
- [Share clipboard between Mac and Windows](https://phun333.github.io/ShareClick/share-clipboard-between-mac-and-windows.md)
- [Pricing](https://phun333.github.io/ShareClick/pricing.md)
- [Install help](https://github.com/phun333/ShareClick/blob/main/docs/INSTALL.md)
