# tappd simulator

This is a simple tool to simulate the behavior of TAPPD service, which is part of [DStack](https://github.com/dstack-TEE/dstack/) and helps you build your own confidential app easily.

## Usage

The Simulator is shipped with prebuilt binaries, which you can download and run as they are ready to use:

For Linux:

```shell
wget https://github.com/Leechael/tappd-simulator/releases/download/v0.1.4/tappd-simulator-0.1.4-x86_64-linux-musl.tgz
tar -xvf tappd-simulator-0.1.4-x86_64-linux-musl.tgz
cd tappd-simulator-0.1.4-x86_64-linux-musl
./tappd-simulator -l unix:/tmp/tappd.sock
```

For Mac:

```shell
wget https://github.com/Leechael/tappd-simulator/releases/download/v0.1.4/tappd-simulator-0.1.4-aarch64-apple-darwin.tgz
tar -xvf tappd-simulator-0.1.4-aarch64-apple-darwin.tgz
cd tappd-simulator-0.1.4-aarch64-apple-darwin
./tappd-simulator -l unix:/tmp/tappd.sock
```

Once the Simulator is running, it will listen on the Unix socket `/tmp/tappd.sock` in the above example. You can verify it's working with the following cURL command:

```shell
curl --unix-socket /tmp/tappd.sock http://dstack/prpc/Tappd.TdxQuote
```

## SDK

To work with the simulator more easily, we recommend developing with our SDK, which handles the communication perfectly. We currently provide SDKs for JavaScript/TypeScript, Python, and Golang.

### JavaScript/TypeScript

You can find it on NPM: https://www.npmjs.com/package/@phala/dstack-sdk

Install:

```shell
npm install --save @phala/dstack-sdk

# bun
bun add @phala/dstack-sdk

# yarn
yarn add @phala/dstack-sdk
```

### Python

You can find it on PyPI: https://pypi.org/project/dstack-sdk

Install:

```shell
pip install dstack-sdk
```

### Golang

TODO.

## API

TODO.

## Build

The build has been tested on Ubuntu 20.04 LTS, MacOS 15.0.1 with Apple Silicon, and Windows 10.

For Linux, you can build either a musl-based portable version or a glibc-based version:

```bash
cargo build --release
# You may need to run `rustup target add x86_64-unknown-linux-musl` first.
cargo build --release --target x86_64-unknown-linux-musl
```