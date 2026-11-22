# Packet Flow

[![License](https://img.shields.io/github/license/rmuraix/pf)](./LICENSE)
[![Build](https://github.com/rmuraix/pf/actions/workflows/build.yml/badge.svg)](https://github.com/rmuraix/pf/actions/workflows/build.yml)  
Simple packet capture

![screen shot](./static/pf_screenShot.png)

## Installation

```shell
cargo install --git https://github.com/rmuraix/pf
```

## Usage

```shell
sudo pf -i <NETWORK INTERFACE>
```

```
Options:
  -i, --interface <NETWORK INTERFACE>  Name of the network interface
      --noudp                          Do not display UDP
      --no-color                       Disable ANSI colors in output (or set NO_COLOR)
  -h, --help                           Print help
  -V, --version                        Print version
```

## Requirement

There are requirements to build for Windows.  
https://github.com/libpnet/libpnet#windows

## Contributing

Your contribution is always welcome. Please read [Contributing Guide](.github/CONTRIBUTING.md).
