# onionchat

`onionchat` is a privacy-focused CLI chat application by A A Hasnat for direct peer-to-peer text exchange over Tor onion services.

Links:
- GitHub Pages site: https://deadsec07.github.io/onionchat/
- GitHub: https://github.com/deadsec07/onionchat
- Main site: https://hnetechnologies.com/
- Creator profile: https://deadsec07.github.io/

It is intentionally small:

- No accounts
- No phone numbers
- No email
- No cloud backend
- No telemetry
- No GUI
- No file transfer

The current MVP uses:

- Rust
- Tor control port integration
- `SAFECOOKIE` authentication when Tor offers it
- Tor v3 onion services for inbound reachability
- Tor SOCKS for outbound delivery
- Signed invite export and import for contact exchange
- Direct chat and invite-only group fan-out
- A simple length-prefixed JSON message frame

## Status

This is a realistic MVP, not a finished secure messenger. It is suitable as a clean base for a real open-source privacy tool, but it does not claim to make users untrackable.

## Build

### Linux / macOS

```bash
cargo build --release
```

### Android via Termux

```bash
pkg update
pkg install rust clang pkg-config tor
cargo build --release
```

## Configuration

The app creates:

- `config.toml`
- `identity.json`
- `peers.json`
- `groups.json`

See the repository README history and project site for the full threat model, protocol notes, and usage examples.
