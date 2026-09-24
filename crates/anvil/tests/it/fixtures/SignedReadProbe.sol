// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Source for the `SIGNED_READ_PROBE_DEPLOY` bytecode used by the anvil tests in
// `../seismic.rs`. Stock Solidity — reads the `signed_read` flag from the 0x6A
// tx-context precompile via `staticcall` with the 1-byte selector 0x01 (an empty
// input would return the tx type instead). A signed read and a mined Seismic
// write are both tx type 74; this flag is the finer read-vs-write distinction.
// See `README.md` for the compile command that reproduces the committed bytecode.
contract SignedReadProbe {
    uint256 public lastFlag; // slot 0
    address constant TX_CONTEXT = address(0x6A);

    function _signedRead() private view returns (uint256 v) {
        (bool ok, bytes memory ret) = TX_CONTEXT.staticcall(hex"01");
        require(ok && ret.length == 32, "TX_CONTEXT");
        v = abi.decode(ret, (uint256));
    }

    // requireSignedRead() [selector 6cac1460]: reverts unless signed_read == 1.
    // Revert-vs-success keeps the assertion readable without decrypting the
    // seismic_call response, which a signed read returns encrypted.
    function requireSignedRead() external view {
        require(_signedRead() == 1);
    }

    // flag() [selector 890eba68]: returns signed_read directly. Usable where the
    // response comes back in plaintext (a plain, unauthenticated eth_call).
    function flag() external view returns (uint256) {
        return _signedRead();
    }

    // record() [selector 266cf109]: persists the flag seen by a *mined* tx into
    // slot 0, which stays readable in plaintext via eth_getStorageAt.
    function record() external {
        lastFlag = _signedRead();
    }
    // lastFlag() [selector 30b93e8a] is the auto-generated getter for slot 0.
}
