// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";

abstract contract Multicall is Context {
    // [AUDIT OBSERVATION - EVM `delegatecall` Context]:
    // `Address.functionDelegateCall(address(this), data[i])` executes `data[i]` in the context of `this`:
    //   - `msg.sender` is PRESERVED from the outer call (still `trustedForwarder` when called via `BasicForwarder`).
    //   - `msg.data` is REPLACED with `data[i]` (stripping the outer forwarder's appended `request.from` address!).
    // - Remediation (OpenZeppelin CVE-2023-49795 fix):
    //   Re-append `_msgSender()` (or the outer context suffix) to each `data[i]` before `delegatecall`.
    function multicall(bytes[] calldata data) external virtual returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            results[i] = Address.functionDelegateCall(address(this), data[i]);
        }
        return results;
    }
}
