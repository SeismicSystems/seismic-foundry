# Gas-payment wire vectors

`gas-payment.json` is an exact copy of the shared SDK fixture at
[`seismic/clients/test-vectors/gas-payment.json`](https://github.com/SeismicSystems/seismic/blob/m/gas-token-registry/clients/test-vectors/gas-payment.json).
The vectors originate from the Rust `seismic-alloy-consensus` codecs and signing
hashes; this copy keeps standalone Foundry tests independent of sibling checkouts.

SHA-256: `18e369680d0fe65733605200519237d02f9dcd6a9d42ca6a59ca992a9916ae77`.

The focused raw-decoder test covers all 36 vectors: Auto/Native/Token,
raw/EIP-712 signing, and nonce boundary cases. Signed-read vectors must remain
rejected by the strict decoder; write vectors must preserve their bytes, selector,
transaction hash, signing hash, and recovered signer.

When the protocol fixtures change, replace this file from the shared source and
update its checksum. Do not regenerate expected bytes using the decoder under test.
