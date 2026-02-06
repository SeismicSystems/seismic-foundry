# seismic-foundry

Seismic Foundry is a fork of [Foundry](https://github.com/foundry-rs/foundry), customized to work with the Seismic blockchain.
It provides a testing toolchain specifically designed for Seismic's [modified version](https://github.com/SeismicSystems/seismic-reth) of Reth.

## Overview

This repository contains modified versions of Foundry's core tools:
- [`sforge`](https://github.com/SeismicSystems/seismic-foundry/tree/seismic/crates/forge): Seismic's version of `forge`, for testing Ethereum smart contracts
- [`sanvil`](https://github.com/SeismicSystems/seismic-foundry/tree/seismic/crates/anvil): Seismic's version of `anvil`, for running local Ethereum test networks
- [`scast`](https://github.com/SeismicSystems/seismic-foundry/tree/seismic/crates/cast): Seismic's version of `cast`, for interacting with Ethereum
> **NOTE:** seismic-foundry does not yet support Foundry's `chisel`

For details about Seismic's modifications to Reth, please see:
- seismic-reth's [README](https://github.com/SeismicSystems/seismic-reth/blob/seismic/README.md)
- Seismic's [Features](https://github.com/SeismicSystems/seismic-reth/blob/seismic/seismic-features.md)

## Installation

In most cases you should install foundry tools via [sfoundryup](https://docs.seismic.systems/getting-started/installation).
If you are modifying seismic-foundry or need to build from source, then you can install from source as described below.

### Seismic Forge
To build `sforge` from source, run this from the root of this repository:
```sh
cargo install --root=$HOME/.seismic --path ./crates/forge --locked
```

### Seismic Anvil
To build `sanvil` from source, run this from the root of this repository:
```sh
cargo install --root=$HOME/.seismic --path ./crates/anvil --locked
```

### Seismic Cast
To build `scast` from source, run this from the root of this repository:
```sh
cargo install --root=$HOME/.seismic --path ./crates/cast --locked
```

## Acknowledgments

This project is built upon the excellent work of the [Foundry](https://github.com/foundry-rs/foundry) Contributors. We are grateful for their contributions to the Ethereum development ecosystem.

## License

This project is distributed under the same license as Foundry.
