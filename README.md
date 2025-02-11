# seismic-foundry

Seismic Foundry is a fork of [Foundry](https://github.com/foundry-rs/foundry), customized to work with the Seismic blockchain. It provides a testing toolchain specifically designed for Seismic's [modified version](https://github.com/SeismicSystems/seismic-reth) of reth

## Overview

This repository contains modified versions of Foundry's core tools:
- [`sforge`](https://github.com/SeismicSystems/seismic-foundry/tree/seismic/crates/forge): Seismic's version of `forge`, for testing Ethereum smart contracts
- [`sanvil`](https://github.com/SeismicSystems/seismic-foundry/tree/seismic/crates/anvil): Seismic's version of `anvil`, for running local Ethereum test networks
> **NOTE:** seismic-foundry does not yet support foundry's `cast` or `chisel`

For details about Seismic's modifications to reth, please see:
- seismic-reth's [README](https://github.com/SeismicSystems/seismic-reth/blob/seismic/README.md)
- Seismic's [Features](https://github.com/SeismicSystems/seismic-reth/blob/seismic/seismic-features.md)

## Installation

### Seismic Forge
To build `sforge` from source, run this from the root of this repository:
```sh
git checkout seismic
cargo install --root=$HOME/.seismic --profile dev --path ./crates/forge --locked
```

### Seismic Anvil
To build `sanvil` from source, run this from the root of this repository:
```sh
git checkout seismic
cargo install --root=$HOME/.seismic --profile dev --path ./crates/anvil --locked
```

## Acknowledgments

This project is built upon the excellent work of the [Foundry Contributors](https://github.com/foundry-rs/foundry). We are grateful for their contributions to the Ethereum development ecosystem.

## License

This project is distributed under the same license as Foundry.
