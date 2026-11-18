// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

interface IFlashLoanEtherReceiver {
    function execute() external payable;
}

contract SideEntranceLenderPool {
    mapping(address => uint256) public balances;

    error RepayFailed();

    event Deposit(address indexed who, uint256 amount);
    event Withdraw(address indexed who, uint256 amount);

    // [AUDIT OBSERVATION - Window 2 (Savings Window)]:
    // Credits `balances[msg.sender]` with `msg.value` AND increases `address(this).balance`.
    // Notice there is NO `nonReentrant` guard preventing `deposit()` from being called
    // while a `flashLoan()` is actively in progress!
    function deposit() external payable {
        unchecked {
            balances[msg.sender] += msg.value;
        }
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];

        delete balances[msg.sender];
        emit Withdraw(msg.sender, amount);

        SafeTransferLib.safeTransferETH(msg.sender, amount);
    }

    // [AUDIT VULNERABILITY - Cross-Function Reentrancy / Shared ETH Accounting]:
    // 1. Dual Accounting Collision:
    //    - `deposit()` and `withdraw()` track individual user ownership via `balances[msg.sender]`.
    //    - `flashLoan()` verifies repayment solely via total contract balance (`address(this).balance >= balanceBefore`).
    // 2. Attack Vector ("The Bank with Two Windows"):
    //    - A borrower takes a flash loan of 1,000 ETH from Window 1 (`flashLoan`).
    //    - Inside `execute()`, the borrower walks to Window 2 (`deposit`) and deposits that same
    //      1,000 ETH back into the pool under their own account (`balances[borrower] = 1,000 ETH`).
    //    - `address(this).balance` returns to 1,000 ETH, satisfying `flashLoan`'s repayment check!
    //    - After `flashLoan` completes, the borrower calls `withdraw()` to drain all 1,000 ETH.
    // 3. Remediation:
    //    - Add a `nonReentrant` modifier to `deposit()`, `withdraw()`, and `flashLoan()`, OR
    //    - Separate flash loan repayment accounting from user deposit accounting.
    function flashLoan(uint256 amount) external {
        uint256 balanceBefore = address(this).balance;

        IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();

        if (address(this).balance < balanceBefore) {
            revert RepayFailed();
        }
    }
}
