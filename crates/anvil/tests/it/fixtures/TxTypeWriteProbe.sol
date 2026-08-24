// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Source for the `TXTYPE_WRITE_PROBE_DEPLOY` bytecode used by the anvil tests
// in `../seismic.rs`. Unlike the read probe, this is a state-changing contract:
// `record()` persists the tx type seen during execution into storage slot 0, so
// a *mined* Seismic write can be shown to observe type 74 (not just eth_call).
// See `README.md` for the compile command that reproduces the committed bytecode.
contract TxTypeWriteProbe {
    uint256 public lastType; // slot 0
    address constant TX_TYPE = address(0x6A);

    // record() [selector 266cf109]: staticcalls 0x6A and stores the tx type.
    function record() external {
        (bool ok, bytes memory ret) = TX_TYPE.staticcall("");
        require(ok && ret.length == 32, "TX_INFO");
        lastType = abi.decode(ret, (uint256));
    }
    // lastType() [selector 9f9a32b0] is the auto-generated getter for slot 0.
}
