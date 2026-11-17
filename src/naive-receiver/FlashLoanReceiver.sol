// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import {WETH, NaiveReceiverPool} from "./NaiveReceiverPool.sol";

contract FlashLoanReceiver is IERC3156FlashBorrower {
    address private pool;

    constructor(address _pool) {
        pool = _pool;
    }

    // [AUDIT VULNERABILITY #1]: Missing Flash Loan Initiator Check (Access Control / Fee Griefing)
    // - Notice the first parameter (`address initiator`) has NO variable name!
    // - In Solidity, unnamed parameters mean the developer ignored that input.
    // - While the assembly block below authenticates `caller() == pool` (immediate caller),
    //   it NEVER checks `initiator == address(this)` (or a trusted owner).
    // - Attack Vector: Any external user can call `pool.flashLoan(receiver, weth, 0, "")`
    //   10 times in a row, forcing this contract to pay 1 WETH in fees each time until drained.
    function onFlashLoan(address, address token, uint256 amount, uint256 fee, bytes calldata)
        external
        returns (bytes32)
    {
        assembly {
            // gas savings

            // NOTES:
            // 1. SLOAD is an EVM opcode that reads a value from contract storage.
            // 2. caller() is the assembly equivalent of: msg.sender.
            // 3. EQ is an EVM opcode that compares two values. Returns 1 if they are equal, 0 otherwise.
            // 4. MSTORE writes 32 bytes (256 bits) into EVM memory.
            // 5. REVERT stops execution and reverts state changes, returning data from memory.
            if iszero(eq(sload(pool.slot), caller())) {
                mstore(0x00, 0x48f5c3ed)
                revert(0x1c, 0x04)
            }
        }

        if (token != address(NaiveReceiverPool(pool).weth())) revert NaiveReceiverPool.UnsupportedCurrency();

        uint256 amountToBeRepaid;
        unchecked {
            amountToBeRepaid = amount + fee;
        }

        _executeActionDuringFlashLoan();

        // [AUDIT OBSERVATION - Follow the Money]:
        // This is the ONLY line where funds leave `FlashLoanReceiver`.
        // Because `fee` is hardcoded to 1 WETH in the pool, every call drains 1 WETH of principal.
        // Return funds to pool
        WETH(payable(token)).approve(pool, amountToBeRepaid);

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    // Internal function where the funds received would be used
    function _executeActionDuringFlashLoan() internal {}
}
