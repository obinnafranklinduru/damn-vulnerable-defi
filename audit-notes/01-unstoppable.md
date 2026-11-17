# Challenge 01: Unstoppable — Audit Write-Up & Learning Notes

- **Category:** Denial of Service (DoS) / ERC-4626 Vault Accounting
- **Contracts in Scope:**
  - [`src/unstoppable/UnstoppableVault.sol`](../src/unstoppable/UnstoppableVault.sol)
  - [`src/unstoppable/UnstoppableMonitor.sol`](../src/unstoppable/UnstoppableMonitor.sol)
- **Test File:** [`test/unstoppable/Unstoppable.t.sol`](../test/unstoppable/Unstoppable.t.sol)

---

## 1. Scenario & Objective

An ERC-4626 tokenized vault (`UnstoppableVault`) holds **1,000,000 DVT** tokens and offers free EIP-3156 flash loans during a 30-day grace period. An on-chain monitoring contract (`UnstoppableMonitor`) owns the vault and calls `checkFlashLoan(100e18)` to test liveness. If the flash loan ever reverts, the monitor catches the failure, pauses the vault (`vault.setPause(true)`), and transfers ownership back to `deployer`.

Starting as `player` with **10 DVT**, my goal is to halt the vault so it stops offering flash loans.

---

## 2. My Initial Understanding

Before diving deep into the exploit, I needed to understand how an **ERC-4626 Tokenized Vault** keeps track of money:

- **`totalSupply`:** Represents the total number of unredeemed vault share tokens (`tDVT`) currently in circulation across all users.
- **`balanceBefore` (`totalAssets()`):** A snapshot of the vault's underlying money (`DVT`) right before the flash loan starts, queried via `asset.balanceOf(address(this))`.
- **How they stay synchronized:**
  - **Deposits:** New underlying assets come in $\rightarrow$ a matching amount of new vault shares are minted.
  - **Withdrawals:** Vault shares are burned $\rightarrow$ a matching amount of underlying assets are paid out.

My key realization right away was:

> _"The math stays perfectly balanced as long as nobody sends tokens directly to the vault contract as a 'donation'."_

---

## 3. Pain Points & Nuances Investigated

While the concept of a direct token "donation" made intuitive sense, looking closely at line 85 of `UnstoppableVault.sol` revealed a deeper subtlety in how the developer wrote the invariant check:

```solidity
uint256 balanceBefore = totalAssets();
if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();
```

### Why did `convertToShares(totalSupply) == balanceBefore` work initially?

In Solmate's `ERC4626.sol`, `convertToShares` is defined as:

```solidity
function convertToShares(uint256 assets) public view virtual returns (uint256) {
    uint256 supply = totalSupply; // Saves an extra SLOAD if totalSupply is non-zero.
    return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
}
```

1. **Dimensional / Unit Mismatch:**
   `convertToShares(uint256 assets)` expects an amount of **underlying assets** (`DVT`) and converts it into **shares** (`tDVT`). However, the developer passed `totalSupply`—which is _already_ in units of shares!
2. **Why the unit tests didn't catch the developer's mistake:**
   At deployment, `deployer` deposited `1,000,000e18` DVT and received `1,000,000e18` shares. Because the ratio between `totalSupply` and `totalAssets()` started at exactly `1:1`, `convertToShares(1_000_000e18)` returned `1,000,000e18`, matching `balanceBefore` (`1,000,000e18`).

---

## 4. Vulnerability Analysis & Exploit Mechanics

### Root Cause

`UnstoppableVault.flashLoan()` enforces a **strict equality check** (`!=`) between two values that are updated through different paths:

1. `totalSupply`: Only updated when users interact with ERC-4626 `deposit()` / `mint()` / `withdraw()` / `redeem()`.
2. `totalAssets()` (`balanceBefore`): Queries `asset.balanceOf(address(this))`, which changes on **any** ERC-20 transfer to the vault's address.

### Tracing the State Desynchronization

When I transfer my `10 DVT` (or even `1 wei` of DVT) directly to `address(vault)` via `token.transfer(address(vault), 10e18)`:

| State Variable / Expression                         | Before Direct Transfer | After `10 DVT` Direct Transfer                                           |
| :-------------------------------------------------- | :--------------------- | :----------------------------------------------------------------------- |
| **`totalAssets()` (`balanceBefore`)**               | `1,000,000e18`         | `1,000,010e18` (+10 DVT)                                                 |
| **`totalSupply`**                                   | `1,000,000e18`         | `1,000,000e18` (Unchanged!)                                              |
| **`convertToShares(totalSupply)`**                  | `1,000,000e18`         | $1,000,000 \times \frac{1,000,000}{1,000,010} \approx 999,990\text{e18}$ |
| **`convertToShares(totalSupply) == balanceBefore`** | `true`                 | **`false` $\rightarrow$ Reverts with `InvalidBalance()`!**               |

### Impact

1. Every subsequent call to `vault.flashLoan(...)` permanently reverts at line 85 with `InvalidBalance()`.
2. When `monitorContract.checkFlashLoan(100e18)` runs inside `_isSolved()`, the `try vault.flashLoan(...)` block fails and enters the `catch` block:

   ```solidity
   try vault.flashLoan(this, asset, amount, bytes("")) {
       emit FlashLoanStatus(true);
   } catch {
       emit FlashLoanStatus(false);
       vault.setPause(true);
       vault.transferOwnership(owner);
   }
   ```

3. The vault is paused and ownership reverts to `deployer`.

### Exploit Implementation (`test/unstoppable/Unstoppable.t.sol`)

```solidity
function test_unstoppable() public checkSolvedByPlayer {
    // Even 1 wei of DVT is sufficient to break the strict equality check.
    token.transfer(address(vault), INITIAL_PLAYER_TOKEN_BALANCE);
}
```

---

## 5. Lessons Learned & Personal Audit Notes

### What to Look For in Future Audits

- **Never trust strict equality (`==`) with `balanceOf(address(this))` or `address(this).balance`:**
  In the EVM, **you cannot prevent a contract from receiving ERC-20 tokens** (via direct `transfer()`) **or native ETH** (via `selfdestruct(target)`, beacon chain withdrawals, or pre-deployment address funding).
- **Check Units on Math Conversions:**
  Whenever I see ERC-4626 helper calls (`convertToShares`, `convertToAssets`, `previewDeposit`, `previewMint`), I should immediately check the units of the variable being passed in. Passing `totalSupply` (shares) into `convertToShares(assets)` is a classic unit-confusion bug.
- **How Production Protocols Solve This:**
  - Track deposited balances via an internal state variable (e.g., `uint256 public totalDeposits`) rather than `asset.balanceOf(address(this))`.
  - Or provide a permissionless recovery/sync function (like Uniswap V2's `skim()` and `sync()`) to sweep or absorb unsolicited token transfers so the protocol cannot be bricked.
