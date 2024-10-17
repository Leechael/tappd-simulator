# tappd simulator

This is a simple tool to simulate the behavior of TAPPD service, which part of dstack and build your own confidential app easily.

## Build

Build tested under Ubuntu 20.04 LTS, MacOS 15.0.1 + Silicon, and Windows 10.

For linux, you can build either musl based portable version or glibc based version:

```bash
cargo build --release
# Your may need run `rustup target add x86_64-unknown-linux-musl` first.
cargo build --release --target x86_64-unknown-linux-musl
```
