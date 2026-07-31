# TXTYPE anvil test fixtures

Sources for the probe bytecode embedded in [`../seismic.rs`](../seismic.rs).
Both are stock Solidity: they read the current transaction's EIP-2718 type byte
from the `0x6A` tx-type precompile via `staticcall` — no compiler builtin, no
`ssolc` change.

| Source | Constant in `seismic.rs` | Purpose |
|---|---|---|
| `TxTypeProbe.sol` | `TXTYPE_PROBE_DEPLOY` | read probe: `isSeismic()` / `requireSeismic()` (eth_call, estimate) |
| `TxTypeWriteProbe.sol` | `TXTYPE_WRITE_PROBE_DEPLOY` | write probe: `record()` stores the tx type from a *mined* tx |

## Reproducing the committed bytecode

Compiled with the Seismic Solidity build (`ssolc`, no optimizer, Mercury):

```sh
solc --bin --evm-version mercury TxTypeProbe.sol
solc --bin --evm-version mercury TxTypeWriteProbe.sol
```

The **code** portion (everything before the trailing `a264…` CBOR metadata) is
byte-for-byte identical to the corresponding constant. The metadata suffix
encodes the compiler version/source hash and is not consensus-relevant; the
committed constants were produced with `ssolc 0.8.31-develop.2026.7.20+commit.fd5f389c`.
