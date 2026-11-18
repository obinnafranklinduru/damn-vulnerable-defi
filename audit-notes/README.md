# Smart Contract Security & Audit Knowledge Base (Damn Vulnerable DeFi v4)

This repository contains my personal, first-person technical write-ups and audit notes as I work through **Damn Vulnerable DeFi v4**.

Rather than just storing final exploit scripts, these notes are structured like deep-dive security research write-ups (inspired by [Hackyboiz's smart contract security series](https://hackyboiz.github.io/2025/09/07/d4tura/smartcontracts/en/)). They capture my actual thought process—including my initial assumptions, where I got stuck or confused, how I learned to interrogate the code line by line, the underlying EVM mechanics, and the mental checklists I am building for real-world audit contests and technical interviews.

---

## Challenge Write-Ups

| #      | Challenge          | Core Vulnerability Classes                                                                                                | Key Standards & EVM Concepts                                                                                                              | Notes Link                                     |
| :----- | :----------------- | :------------------------------------------------------------------------------------------------------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------- |
| **01** | **Unstoppable**    | • Strict Balance Equality (DoS)<br>• Internal vs. External Accounting Desync<br>• Dimensional / Unit Mismatch             | • ERC-4626 Tokenized Vaults<br>• EIP-3156 Flash Loans<br>• Direct ERC-20 Transfers ("Donations")                                          | [01-unstoppable.md](./01-unstoppable.md)       |
| **02** | **Naive Receiver** | • Missing Callback Initiator Auth (Fee Griefing)<br>• ERC-2771 `_msgSender()` Spoofing via `Multicall` (`CVE-2023-49795`) | • EIP-3156 Callbacks & Inline Assembly<br>• ERC-2771 Meta-Transactions & EIP-712<br>• `delegatecall` Context (`msg.sender` vs `msg.data`) | [02-naive-receiver.md](./02-naive-receiver.md) |
| **03** | **Truster**        | • Arbitrary External Call (`target.functionCall(data)`)<br>• ERC-20 Allowance Hijacking (`approve` + `transferFrom`)      | • Constructor Transaction Batching (`nonce == 1`)<br>• ERC-20 `spender` (`msg.sender`) vs `recipient` (`to`)                              | [03-truster.md](./03-truster.md)               |
| **04** | **Side Entrance**  | • Cross-Function Reentrancy ("Two Windows")<br>• Shared Balance vs. Internal Ledger Desync                                | • Native ETH Callbacks (`receive()`)<br>• `SafeTransferLib.safeTransferETH` vs `.transfer()`<br>• `immutable` Storage Optimization        | [04-side-entrance.md](./04-side-entrance.md)   |

---

## My Core Auditor's Mental Checklist (Growing Reference)

Whenever I open an unfamiliar smart contract in an audit or interview, I follow this sequence:

1. **Follow the Money Going Out:**
   - Scan every contract for functions that move value out (`transfer`, `transferFrom`, `approve`, `withdraw`, low-level `.call{value: ...}`).
   - Ask: _What guards this line? Whose balance is being deducted?_
2. **Spot Unnamed Function Parameters (Red Flag):**
   - If a function signature has an unnamed parameter like `function onFlashLoan(address, address token, ...)` or `function flashFee(address token, uint256)`, **stop immediately**.
   - Developers leave parameters unnamed when they ignore them. Ask: _What security check or calculation was supposed to use that ignored input?_
3. **Never Trust Strict Equality on Token/ETH Balances:**
   - Compare internal accounting (`totalSupply`, `deposits[user]`, `reserves`) against external balance queries (`token.balanceOf(address(this))`, `address(this).balance`).
   - Remember: Anyone can force-feed ERC-20 tokens via direct `transfer()` or native ETH via `selfdestruct` / coinbase rewards.
4. **Trace Context Across `delegatecall` and Composability Boundaries:**
   - `delegatecall` preserves `msg.sender` and `msg.value`, but **replaces `msg.data`** with the inner call's calldata.
   - When two safe modules (like `ERC2771Context` and `Multicall`) are inherited together, check if one module's assumptions about `msg.data` or `msg.sender` are broken by the other!
5. **Hunt for Arbitrary External Calls (`target.call(data)` / `target.functionCall(data)`):**
   - If a contract holding funds (or holding user token approvals) executes a user-supplied `target` and `data`, it can be forced to call `token.approve(attacker, amount)` as itself, bypassing `balanceOf` checks completely!
6. **Check for Cross-Function Reentrancy ("The Bank with Two Windows"):**
   - Even if `withdraw()` follows Checks-Effects-Interactions (CEI), check whether a borrower inside `flashLoan()` can re-enter the contract via `deposit()` (or `mint()`) using the borrowed funds, satisfying `address(this).balance >= balanceBefore` while double-counting those funds in `balances[msg.sender]`!
