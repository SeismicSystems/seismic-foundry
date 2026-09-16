# Seismic Developer Tools

The Seismic Foundry Developer Tools extend the existing Foundry suite by providing specialized binaries (`sforge`, `sanvil`, and `scast`) that support shielded/Seismic smart contract development. These tools integrate advanced functionalities—including a dedicated Solidity compiler (`ssolc`) and an enhanced EVM (SEVM)—that natively support shielded transactions and private storage.

---

## Table of Contents
1. [Overview](#1-overview)
2. [Changes](#2-changes)
   - [2.1 sforge](#21-sforge)
   - [2.2 sanvil](#22-sanvil)
   - [2.3 scast](#23-scast)
3. [Technical Details](#3-technical-details)
   - [3.1 Private Storage Implementation in sanvil](#31-private-storage-implementation-in-sanvil)
   - [3.2 Development vs Production](#32-development-vs-production)

---

## 1. Overview

The Seismic Foundry suite consists of three main components:
- `sforge`: A specialized testing framework for shielded contracts, an extension of [`forge`](https://book.getfoundry.sh/forge/)
- `sanvil`: A local Seismic node supporting private storage and transactions, an extension of [`anvil`](https://book.getfoundry.sh/anvil/)
- `scast`: A CLI for interacting with Seismic networks with client-side encryption support, an extension of [`cast`](https://book.getfoundry.sh/cast/)

---

## 2. Changes

### 2.1 sforge
The following changes are made in order to support the development, testing and deployment of shielded contracts using `sforge`:
- In the overall config (`config/src/lib.rs`), we add the [`seismic`](https://github.com/SeismicSystems/seismic-foundry/blob/b05fd187442241ab47ec992c44a105c2ee97f5a8/crates/config/src/lib.rs#L507) flag in order to use the Seismic Solidity compiler (`ssolc`). This flag is set to `true` by default.
- The flag, when set to `true`, will use the Seismic Solidity compiler (`ssolc`) situated at `/usr/local/bin/ssolc`.
Developers are hence required to have the `ssolc` binary installed at this location before using `sforge`. The latest `ssolc` binary is automatically installed when using `sfoundryup`.

### 2.2 sanvil
The following changes are made in order to support deployment and testing of shielded contracts and transactions using `sanvil`:
- Private storage and transaction support is the same as in [`seismic-reth`](https://github.com/SeismicSystems/documentation/blob/main/reth/documentation.md), in order to make the node privacy-aware and support shielded transactions.
- Since `sanvil` is a local node, encryption/decryption occurs natively within the node, instead of within a TEE as is done in `seismic-reth`.
- Both `sanvil` and `sforge` are configured to use the Seismic EVM (`SEVM`) version specified in the [`seismic_version`](https://github.com/SeismicSystems/seismic-foundry/blob/b05fd187442241ab47ec992c44a105c2ee97f5a8/crates/config/src/lib.rs#L217) field in the overall config (`config/src/lib.rs`) if set.

### 2.3 scast
The following changes are made to support interacting with Seismic networks using `scast`:
- **`scast send --seismic [ENCRYPTION_PRIVATE_KEY]`**: Adds client-side encryption for send transactions. When the `--seismic` flag is provided, `scast` encrypts the transaction input data before sending. An optional encryption private key can be provided; if omitted, a random key is generated. The encrypted transaction is sent as a Seismic transaction type (`TxSeismic`), with encryption parameters (public key, nonce, message version, block hash, expiry) bundled into `TxSeismicElements`.
- **`scast call --encryption-private-key [KEY]`**: Adds client-side encryption/decryption for call (read) transactions. Call data is encrypted and sent via `seismic_call()` RPC, and the response is decrypted before being returned.
- Both commands fetch the TEE public key from the node (via `get_tee_pubkey()` RPC) to perform secp256k1 key exchange for encryption.
- EIP-1559 transactions are converted to legacy gas price format for Seismic compatibility.

---

## 3. Technical Details

### 3.1 Private Storage Implementation in `sanvil`
- Native support for shielded transactions and private storage
- In development environments, encryption/decryption occurs within the node.
- Functionally equivalent to `seismic-reth`, but without TEE requirements.

### 3.2 Development vs Production
- Development: Encryption/decryption performed natively by `sanvil`
- Production: Encryption/decryption handled by TEEs in `seismic-reth`
- API compatibility maintained between environments
