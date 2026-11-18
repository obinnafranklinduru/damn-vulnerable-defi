// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {DamnValuableToken} from "../DamnValuableToken.sol";

contract TrusterLenderPool is ReentrancyGuard {
    using Address for address;

    DamnValuableToken public immutable token;

    error RepayFailed();

    constructor(DamnValuableToken _token) {
        token = _token;
    }

    // [AUDIT VULNERABILITY]: Arbitrary External Call (`target.functionCall(data)`)
    // 1. User-Controlled Target & Calldata:
    //    Unlike EIP-3156 (which calls a fixed `onFlashLoan` selector on `borrower`),
    //    this function lets the caller specify ANY `target` address and ANY `data` bytes!
    // 2. Execution Context (`msg.sender == address(this)`):
    //    When `target.functionCall(data)` executes, the `target` contract sees the Pool
    //    (`address(this)`) as `msg.sender`.
    // 3. Flawed Invariant Assumption:
    //    The pool only checks `token.balanceOf(address(this)) < balanceBefore`.
    //    It assumes that as long as the token balance hasn't decreased during `flashLoan`,
    //    its funds are safe—ignoring ERC-20 `allowance` state changes (`token.approve(...)`)!
    // 4. Remediation:
    //    - Never execute arbitrary user-supplied `(target, data)` calls from a contract holding funds.
    //    - Enforce a strict callback interface (e.g., `IERC3156FlashBorrower(borrower).onFlashLoan(...)`)
    //      and forbid `target == address(token)`.
    function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
        external
        nonReentrant
        returns (bool)
    {
        uint256 balanceBefore = token.balanceOf(address(this));

        token.transfer(borrower, amount);
        target.functionCall(data);

        if (token.balanceOf(address(this)) < balanceBefore) {
            revert RepayFailed();
        }

        return true;
    }
}
