# tx-context anvil test fixtures

Sources for the probe bytecode embedded in [`../seismic.rs`](../seismic.rs).
All are stock Solidity: they read transaction-context flags from the `0x6A`
tx-context precompile via `staticcall` — no compiler builtin, no `ssolc` change.
An empty input returns the EIP-2718 tx type; the 1-byte input `0x01` returns the
`signed_read` flag.

| Source | Constant in `seismic.rs` | Purpose |
|---|---|---|
| `TxTypeProbe.sol` | `TXTYPE_PROBE_DEPLOY` | read probe: `isSeismic()` / `requireSeismic()` (eth_call, estimate) |
| `TxTypeWriteProbe.sol` | `TXTYPE_WRITE_PROBE_DEPLOY` | write probe: `record()` stores the tx type from a *mined* tx |
| `SignedReadProbe.sol` | `SIGNED_READ_PROBE_DEPLOY` | signed-read probe: `requireSignedRead()` (signed read vs plain call) and `record()` (mined write) |

## Reproducing the committed bytecode

Compiled with the Seismic Solidity build (`ssolc`, no optimizer, Mercury):

```sh
solc --bin --evm-version mercury TxTypeProbe.sol
solc --bin --evm-version mercury TxTypeWriteProbe.sol
solc --bin --evm-version mercury SignedReadProbe.sol
```

The **code** portion (everything before the trailing `a264…` CBOR metadata) is
byte-for-byte identical to the corresponding constant. The metadata suffix
encodes the compiler version/source hash and is not consensus-relevant; the
committed constants were produced with `ssolc 0.8.31-develop.2026.7.20+commit.fd5f389c`.
