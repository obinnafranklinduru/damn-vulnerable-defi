// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {IERC3156FlashLender} from "@openzeppelin/contracts/interfaces/IERC3156FlashLender.sol";
import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import {FlashLoanReceiver} from "./FlashLoanReceiver.sol";
import {Multicall} from "./Multicall.sol";
import {WETH} from "solmate/tokens/WETH.sol";

contract NaiveReceiverPool is Multicall, IERC3156FlashLender {
    uint256 private constant FIXED_FEE = 1e18; // not the cheapest flash loan
    bytes32 private constant CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");

    WETH public immutable weth;
    address public immutable trustedForwarder;
    address public immutable feeReceiver;

    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;

    error RepayFailed();
    error UnsupportedCurrency();
    error CallbackFailed();

    constructor(address _trustedForwarder, address payable _weth, address _feeReceiver) payable {
        weth = WETH(_weth);
        trustedForwarder = _trustedForwarder;
        feeReceiver = _feeReceiver;
        _deposit(msg.value);
    }

    function maxFlashLoan(address token) external view returns (uint256) {
        if (token == address(weth)) return weth.balanceOf(address(this));
        return 0;
    }

    // [AUDIT OBSERVATION]: Second parameter (`uint256 amount`) is unnamed/ignored.
    // Even if `amount == 0`, the pool still charges `FIXED_FEE` (1 WETH).
    function flashFee(address token, uint256) external view returns (uint256) {
        if (token != address(weth)) revert UnsupportedCurrency();
        return FIXED_FEE;
    }

    // [AUDIT OBSERVATION]:
    // 1. No access control and no `amount == 0` guard. Anyone can initiate a flash loan
    //    for any `receiver` contract with `amount = 0`.
    // 2. Passes `msg.sender` as the first argument (`initiator`) to `receiver.onFlashLoan(...)`.
    // 3. Credits the 1 WETH `FIXED_FEE` to `deposits[feeReceiver]` (which is `deployer`).
    function flashLoan(IERC3156FlashBorrower receiver, address token, uint256 amount, bytes calldata data)
        external
        returns (bool)
    {
        if (token != address(weth)) revert UnsupportedCurrency();

        // Transfer WETH and handle control to receiver
        weth.transfer(address(receiver), amount);
        totalDeposits -= amount;

        if (receiver.onFlashLoan(msg.sender, address(weth), amount, FIXED_FEE, data) != CALLBACK_SUCCESS) {
            revert CallbackFailed();
        }

        uint256 amountWithFee = amount + FIXED_FEE;
        weth.transferFrom(address(receiver), address(this), amountWithFee);
        totalDeposits += amountWithFee;

        // Fee is credited to `feeReceiver` (`deployer`), NOT the borrower!
        // After 10 flash loans against `receiver`, `deposits[deployer]` grows from 1,000 WETH to 1,010 WETH.
        deposits[feeReceiver] += FIXED_FEE;

        return true;
    }

    // [AUDIT OBSERVATION - Follow the Money]:
    // Only function that permanently removes WETH from the pool.
    // Relies on `_msgSender()` to determine whose `deposits[...]` balance to deduct from.
    function withdraw(uint256 amount, address payable receiver) external {
        // Reduce deposits
        deposits[_msgSender()] -= amount;
        totalDeposits -= amount;

        // Transfer ETH to designated receiver
        weth.transfer(receiver, amount);
    }

    function deposit() external payable {
        _deposit(msg.value);
    }

    function _deposit(uint256 amount) private {
        weth.deposit{value: amount}();

        deposits[_msgSender()] += amount;
        totalDeposits += amount;
    }

    // [AUDIT VULNERABILITY #2]: ERC-2771 `_msgSender()` Spoofing via `Multicall` (`delegatecall`)
    // - Assumption: When `msg.sender == trustedForwarder`, the last 20 bytes of `msg.data`
    //   (`msg.data[msg.data.length - 20:]`) was appended by `BasicForwarder.execute` after verifying
    //   the signer's EIP-712 signature.
    // - Why this assumption breaks with `Multicall`:
    //   1. `player` signs a forwarder request calling `pool.multicall(callData)`.
    //   2. `BasicForwarder` calls `pool.multicall(callData)` with `msg.sender = trustedForwarder`
    //      and appends `player` to the outer `msg.data`.
    //   3. Inside `multicall`, each `callData[i]` is executed via `address(this).delegatecall(callData[i])`.
    //   4. `delegatecall` PRESERVES `msg.sender == trustedForwarder`, but REPLACES `msg.data` with `callData[i]`!
    //   5. An attacker can append ANY 20-byte address (e.g., `deployer`) to the end of `callData[i]`,
    //      causing `_msgSender()` inside `withdraw()` to return `deployer`!
    function _msgSender() internal view override returns (address) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            return address(bytes20(msg.data[msg.data.length - 20:]));
        } else {
            return super._msgSender();
        }
    }
}
