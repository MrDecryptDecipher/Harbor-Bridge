// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {HarborToken} from "../src/token/HarborToken.sol";
import {WrappedHarbor} from "../src/token/WrappedHarbor.sol";
import {NativeBridge} from "../src/NativeBridge.sol";
import {WrappedBridge} from "../src/WrappedBridge.sol";
import {StakeOnArrival} from "../src/StakeOnArrival.sol";
import {HarborStaking} from "../src/staking/HarborStaking.sol";
import {IHarborStaking} from "../src/interfaces/IHarborStaking.sol";
import {Message} from "../src/interfaces/IHarborBridge.sol";

contract MockSmartWallet {
    // Contract wallet with code.length > 0
    fallback() external payable {}
}

contract StrictContractWallet {
    // Contract wallet with no fallback/receive - reverts if any unexpected selector is called
}

contract GasConsumingRecipient {
    // Malicious contract that attempts to consume all gas forwarded to it
    receive() external payable {}

    fallback() external payable {
        while (true) {}
    }

    function onBridgeReceived(uint256, address, uint256, bytes calldata) external pure {
        while (true) {}
    }

    function onHookFailure(address, uint256, bytes calldata) external pure {
        while (true) {}
    }
}

contract RevertingHookGasBurningFailureReceiver {
    // Malicious contract: hook reverts, then failure notification attempts unbounded gas burn
    function onBridgeReceived(uint256, address, uint256, bytes calldata) external pure {
        revert("hook failed");
    }

    function onHookFailure(address, uint256, bytes calldata) external pure {
        while (true) {}
    }
}

contract RevertingCallbackReceiver {
    function onBridgeReceived(uint256, address, uint256, bytes calldata) external pure {
        revert("hook failed");
    }
    function onHookFailure(address, uint256, bytes calldata) external pure {
        revert("callback failed");
    }
}

contract MaliciousReenteringReceiver {
    WrappedBridge public bridge;
    Message public message;
    bytes[] public signatures;
    bool public hasReentered;

    constructor(address bridge_) {
        bridge = WrappedBridge(bridge_);
    }

    function setPayload(Message memory msg_, bytes[] memory sigs_) external {
        message = msg_;
        signatures = sigs_;
    }

    function onBridgeReceived(uint256, address, uint256, bytes calldata) external {
        if (!hasReentered) {
            hasReentered = true;
            bridge.mint(message, signatures);
        }
    }

    function onHookFailure(address, uint256, bytes calldata) external {
        if (!hasReentered) {
            hasReentered = true;
            bridge.mint(message, signatures);
        }
    }
}

/// @title StakeOnArrivalTest
/// @notice Comprehensive tests for StakeOnArrival hook receiver on Chain B.
///         Verifies happy paths and failure resilience (pool full, partial cap,
///         unauthorized operator, contract beneficiaries, fallback sender).
contract StakeOnArrivalTest is Test {
    uint256 internal constant CHAIN_A = 8453200012;
    uint256 internal constant CHAIN_B = 1002;
    uint256 internal constant THRESHOLD = 2;

    address internal admin = makeAddr("admin");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    uint256[] internal validatorKeys;
    address[] internal validatorAddresses;

    HarborToken internal token;
    WrappedHarbor internal wrappedToken;
    NativeBridge internal nativeBridge;
    WrappedBridge internal wrappedBridge;
    HarborStaking internal staking;
    StakeOnArrival internal stakeOnArrival;

    function setUp() public {
        _createValidators(3);

        vm.chainId(CHAIN_A);
        token = new HarborToken(admin, admin);
        nativeBridge = new NativeBridge(address(token), CHAIN_B, validatorAddresses, THRESHOLD, admin);

        vm.chainId(CHAIN_B);
        wrappedToken = new WrappedHarbor(admin);
        wrappedBridge = new WrappedBridge(address(wrappedToken), CHAIN_A, validatorAddresses, THRESHOLD, admin);
        vm.prank(admin);
        wrappedToken.setBridge(address(wrappedBridge));

        staking = new HarborStaking(address(wrappedToken), 1 ether, block.timestamp, block.timestamp + 30 days, admin);
        stakeOnArrival = new StakeOnArrival(
            address(wrappedBridge),
            address(wrappedToken),
            address(staking),
            0
        );

        // Staking team setup
        vm.startPrank(admin);
        staking.add(100, address(wrappedToken));
        staking.setOperator(address(stakeOnArrival), true);
        vm.stopPrank();

        // Fund alice on Chain A
        vm.prank(admin);
        token.transfer(alice, 1_000 ether);
    }

    /// Scenario 1: Happy path - EOA locks on A with hook -> wHBR staked on B
    function test_StakeOnArrival_HappyPath_EOA() public {
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 500_000, abi.encode(alice));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msgSent, _sign(msgSent, wrappedBridge));

        assertGt(staking.stakedAmount(0, alice), 0);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 2: Staking pool is at deposit cap (pool full)
    /// Staking fails -> User receives wHBR directly in wallet. Zero funds lost!
    function test_StakeOnArrival_PoolFull_RefundsWHBR() public {
        // Set cap on pool 0 to 1 ether and fill it
        vm.chainId(CHAIN_B);
        vm.prank(admin);
        staking.setDepositCap(0, 1 ether);

        // Fill the pool completely
        deal(address(wrappedToken), admin, 1 ether);
        vm.startPrank(admin);
        wrappedToken.approve(address(staking), 1 ether);
        staking.deposit(0, 1 ether, admin);
        vm.stopPrank();

        // Now alice bridges 100 HBR with hook
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 500_000, abi.encode(alice));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        // Minting does not revert!
        wrappedBridge.mint(msgSent, _sign(msgSent, wrappedBridge));

        // Staking should have 0 for alice because pool was full
        assertEq(staking.stakedAmount(0, alice), 0);

        // But alice received all wHBR directly in her wallet!
        assertGt(wrappedToken.balanceOf(alice), 0);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 3: Partial deposit cap room
    /// Pool has room for 30 wHBR, alice bridges 100 HBR -> 30 staked, 70 refunded to alice
    function test_StakeOnArrival_PartialCap_StakesAndRefundsRemainder() public {
        // Net received from 100 ether with 0.3% fee is 99.7 ether
        // Set cap to 30 ether
        vm.chainId(CHAIN_B);
        vm.prank(admin);
        staking.setDepositCap(0, 30 ether);

        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 500_000, abi.encode(alice));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msgSent, _sign(msgSent, wrappedBridge));

        // Exactly 30 ether is staked
        assertEq(staking.stakedAmount(0, alice), 30 ether);

        // Remainder (99.7 - 30 = 69.7 ether) is delivered directly to alice's balance
        assertEq(wrappedToken.balanceOf(alice), 99.7 ether - 30 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 4: Operator status revoked
    /// Staking fails -> User receives full wHBR without failure
    function test_StakeOnArrival_OperatorRevoked_RefundsWHBR() public {
        vm.chainId(CHAIN_B);
        vm.prank(admin);
        staking.setOperator(address(stakeOnArrival), false);

        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 500_000, abi.encode(alice));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msgSent, _sign(msgSent, wrappedBridge));

        // Alice receives full wHBR
        assertEq(staking.stakedAmount(0, alice), 0);
        assertEq(wrappedToken.balanceOf(alice), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 5: Beneficiary is a smart contract
    /// HarborStaking attributes contract deposits to msg.sender (StakeOnArrival),
    /// which would lock out the contract user from withdrawing.
    /// StakeOnArrival protects user funds by refunding wHBR directly to the contract.
    function test_StakeOnArrival_ContractBeneficiary_RefundsDirectly() public {
        MockSmartWallet wallet = new MockSmartWallet();

        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 500_000, abi.encode(address(wallet)));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msgSent, _sign(msgSent, wrappedBridge));

        // Wallet received the tokens directly; not stuck in StakeOnArrival
        assertEq(wrappedToken.balanceOf(address(wallet)), 99.7 ether);
        assertEq(staking.stakedAmount(0, address(wallet)), 0);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 6: Malformed hookData safely falls back to sender
    function test_StakeOnArrival_MalformedHookData_FallsBackToSender() public {
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        // hookData is shorter than 32 bytes
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 500_000, hex"1234");
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msgSent, _sign(msgSent, wrappedBridge));

        // Fell back to sender (alice)
        assertGt(staking.stakedAmount(0, alice), 0);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 7: Only bridge can call onBridgeReceived
    function test_StakeOnArrival_UnauthorizedCaller_Reverts() public {
        vm.chainId(CHAIN_B);
        vm.prank(bob);
        vm.expectRevert("only bridge");
        stakeOnArrival.onBridgeReceived(CHAIN_A, alice, 100 ether, abi.encode(alice));
    }

    /// Scenario 8: Low hookGasLimit causes onBridgeReceived out-of-gas
    /// Bridge catches failure, calls onHookFailure, StakeOnArrival registers claimable refund, and beneficiary claims it.
    function test_StakeOnArrival_LowGasLimit_AutoRefundsBeneficiary() public {
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        // Give only 5,000 gas limit for the hook (insufficient for onBridgeReceived)
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 5_000, abi.encode(alice));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        // Minting executes with normal gas stipend for the outer tx
        wrappedBridge.mint(msgSent, _sign(msgSent, wrappedBridge));

        // onBridgeReceived failed due to low gas; onHookFailure registered claimable refund for alice
        assertEq(staking.stakedAmount(0, alice), 0);
        assertEq(stakeOnArrival.claimableRefund(alice), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 99.7 ether);
        assertEq(wrappedToken.balanceOf(alice), 0);

        // Alice claims her refund
        vm.prank(alice);
        stakeOnArrival.claimRefund(alice);

        assertEq(wrappedToken.balanceOf(alice), 99.7 ether);
        assertEq(stakeOnArrival.claimableRefund(alice), 0);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 9: If immediate transfer in onHookFailure does not complete, claimableRefund remains claimable
    function test_StakeOnArrival_FailedImmediateTransfer_CanClaimRefund() public {
        vm.chainId(CHAIN_B);
        // Simulate onHookFailure called when StakeOnArrival has no balance to immediately transfer
        vm.prank(address(wrappedBridge));
        stakeOnArrival.onHookFailure(alice, 50 ether, abi.encode(alice));

        // Registered in claimableRefund
        assertEq(stakeOnArrival.claimableRefund(alice), 50 ether);

        // Now fund StakeOnArrival with 50 ether
        deal(address(wrappedToken), address(stakeOnArrival), 50 ether);

        // Alice claims her refund
        vm.prank(alice);
        stakeOnArrival.claimRefund(alice);

        assertEq(stakeOnArrival.claimableRefund(alice), 0);
        assertEq(wrappedToken.balanceOf(alice), 50 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 10: Bob cannot steal Alice's registered refund
    function test_StakeOnArrival_CannotClaimOtherBeneficiaryTokens() public {
        vm.chainId(CHAIN_B);
        vm.prank(address(wrappedBridge));
        stakeOnArrival.onHookFailure(alice, 50 ether, abi.encode(alice));
        deal(address(wrappedToken), address(stakeOnArrival), 50 ether);

        // Bob attempts to claim for himself
        vm.prank(bob);
        vm.expectRevert("no claimable refund");
        stakeOnArrival.claimRefund(bob);

        // Alice's refund is still intact
        assertEq(stakeOnArrival.claimableRefund(alice), 50 ether);
        assertEq(wrappedToken.balanceOf(bob), 0);
    }

    /// Scenario 11: Anyone can trigger claimRefund for beneficiary, but tokens strictly go to beneficiary
    function test_StakeOnArrival_AnyoneCanTriggerClaimForBeneficiary() public {
        vm.chainId(CHAIN_B);
        vm.prank(address(wrappedBridge));
        stakeOnArrival.onHookFailure(alice, 50 ether, abi.encode(alice));
        deal(address(wrappedToken), address(stakeOnArrival), 50 ether);

        // Bob calls claimRefund for alice
        vm.prank(bob);
        stakeOnArrival.claimRefund(alice);

        // Alice receives the tokens, Bob receives 0
        assertEq(wrappedToken.balanceOf(alice), 50 ether);
        assertEq(wrappedToken.balanceOf(bob), 0);
        assertEq(stakeOnArrival.claimableRefund(alice), 0);
    }

    /// Scenario 12: Unrelated users bridging afterwards cannot sweep another user's claimable refund
    function test_StakeOnArrival_UnrelatedUserCannotSweepOrRedistribute() public {
        vm.chainId(CHAIN_B);
        // Alice has an unclaimed registered refund
        vm.prank(address(wrappedBridge));
        stakeOnArrival.onHookFailure(alice, 50 ether, abi.encode(alice));
        deal(address(wrappedToken), address(stakeOnArrival), 50 ether);

        // Now Bob bridges 100 HBR on Chain A with hook to stake
        vm.chainId(CHAIN_A);
        vm.prank(admin);
        token.transfer(bob, 200 ether);

        vm.startPrank(bob);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 500_000, abi.encode(bob));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msgSent, _sign(msgSent, wrappedBridge));

        // Bob's tokens are staked for bob (99.7 ether)
        assertEq(staking.stakedAmount(0, bob), 99.7 ether);
        assertEq(wrappedToken.balanceOf(bob), 0);

        // Alice's 50 ether was NOT swept into Bob's staking or Bob's wallet
        assertEq(stakeOnArrival.claimableRefund(alice), 50 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 50 ether);

        // Alice claims her refund successfully
        vm.prank(alice);
        stakeOnArrival.claimRefund(alice);
        assertEq(wrappedToken.balanceOf(alice), 50 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 13: A repeated recovery attempt cannot transfer the same entitlement twice
    function test_StakeOnArrival_CannotDoubleClaimRefund() public {
        vm.chainId(CHAIN_B);
        vm.prank(address(wrappedBridge));
        stakeOnArrival.onHookFailure(alice, 50 ether, abi.encode(alice));
        deal(address(wrappedToken), address(stakeOnArrival), 50 ether);

        vm.prank(alice);
        stakeOnArrival.claimRefund(alice);
        assertEq(wrappedToken.balanceOf(alice), 50 ether);

        // Repeated claim fails
        vm.prank(alice);
        vm.expectRevert("no claimable refund");
        stakeOnArrival.claimRefund(alice);
    }

    /// Scenario 14: Non-bridge caller cannot call onHookFailure
    function test_StakeOnArrival_OnlyBridgeCanCallOnHookFailure() public {
        vm.chainId(CHAIN_B);
        vm.prank(bob);
        vm.expectRevert("only bridge");
        stakeOnArrival.onHookFailure(alice, 50 ether, abi.encode(alice));
    }

    /// Scenario 15: Malformed hookData with dirty higher bits safely falls back to sender without reverting
    function test_StakeOnArrival_MalformedHookData_DirtyHigherBits_FallsBackToSender() public {
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        // 32 bytes of 0xff (dirty higher 12 bytes)
        bytes memory dirtyBytes = hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 500_000, dirtyBytes);
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msgSent, _sign(msgSent, wrappedBridge));

        // Decoded safely as sender (alice) and staked for alice
        assertEq(staking.stakedAmount(0, alice), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 16: Failure notification OOG causes mint to revert atomically
    function test_WrappedBridge_FailureNotificationOOG_RevertsMint() public {
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 5_000, abi.encode(alice));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        bytes[] memory sigs = _sign(msgSent, wrappedBridge);
        bytes32 digest = wrappedBridge.messageDigest(msgSent);

        // Call mint with insufficient gas to complete onHookFailure
        vm.expectRevert();
        wrappedBridge.mint{gas: 120_000}(msgSent, sigs);

        // Mint was reverted atomically: message was NOT marked executed, tokens were NOT minted
        assertFalse(wrappedBridge.isMessageExecuted(digest));
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
        assertEq(stakeOnArrival.claimableRefund(alice), 0);

        // Now relayer retries with sufficient gas, and it succeeds!
        wrappedBridge.mint(msgSent, sigs);
        assertTrue(wrappedBridge.isMessageExecuted(digest));
        assertEq(stakeOnArrival.claimableRefund(alice), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 99.7 ether);

        // Alice claims her refund
        vm.prank(alice);
        stakeOnArrival.claimRefund(alice);
        assertEq(wrappedToken.balanceOf(alice), 99.7 ether);
    }

    /// Scenario 17: Hook failure callback that reverts causes mint to revert atomically
    function test_WrappedBridge_CallbackReverts_RevertsMint() public {
        RevertingCallbackReceiver badReceiver = new RevertingCallbackReceiver();

        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(badReceiver), 100 ether, 50_000, abi.encode(alice));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        bytes[] memory sigs = _sign(msgSent, wrappedBridge);
        bytes32 digest = wrappedBridge.messageDigest(msgSent);

        // Because badReceiver reverts on onHookFailure, mint reverts atomically
        vm.expectRevert("callback failed");
        wrappedBridge.mint(msgSent, sigs);

        // Atomically rolled back
        assertFalse(wrappedBridge.isMessageExecuted(digest));
        assertEq(wrappedToken.balanceOf(address(badReceiver)), 0);
    }

    /// Scenario 18: Malicious hook receiver attempting reentrancy is blocked
    function test_WrappedBridge_MaliciousHookReceiver_ReentrancyBlocked() public {
        MaliciousReenteringReceiver attackerReceiver = new MaliciousReenteringReceiver(address(wrappedBridge));

        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(attackerReceiver), 100 ether, 50_000, abi.encode(alice));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        bytes[] memory sigs = _sign(msgSent, wrappedBridge);
        attackerReceiver.setPayload(msgSent, sigs);

        // Reentrancy is blocked by nonReentrant
        vm.expectRevert();
        wrappedBridge.mint(msgSent, sigs);
    }

    /// Scenario 19: Normal bridge transfer to contract wallet without hook succeeds
    function test_WrappedBridge_NormalBridgeTransfer_ToContractWallet_Succeeds() public {
        StrictContractWallet wallet = new StrictContractWallet();

        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        // Normal lock to a contract wallet with no hook
        nativeBridge.lock(CHAIN_B, address(wallet), 100 ether);
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        // Mint to contract wallet succeeds even though wallet does not implement onBridgeReceived
        wrappedBridge.mint(msgSent, _sign(msgSent, wrappedBridge));

        assertEq(wrappedToken.balanceOf(address(wallet)), 99.7 ether);
    }

    /// Scenario 20: Normal lock directly to StakeOnArrival safely stakes for sender
    function test_WrappedBridge_NormalLockToStakeOnArrival_SafelyStakesOrRefunds() public {
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        // Normal lock directly to StakeOnArrival with hookGasLimit=0 and hookData=""
        nativeBridge.lock(CHAIN_B, address(stakeOnArrival), 100 ether);
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();
        assertEq(msgSent.hookGasLimit, 0);
        assertEq(msgSent.hookData.length, 0);

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msgSent, _sign(msgSent, wrappedBridge));

        // onBridgeReceived is invoked with gasleft() and safely stakes for sender (alice)
        assertEq(staking.stakedAmount(0, alice), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 21: Multiple beneficiaries with outstanding claims
    function test_StakeOnArrival_MultipleBeneficiaries_OutstandingClaims() public {
        // Alice bridges with low gas -> hook fails -> claim registered
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 5_000, abi.encode(alice));
        vm.stopPrank();
        Message memory msgAlice = _getLastMessage();

        // Bob bridges with low gas -> hook fails -> claim registered
        vm.prank(admin);
        token.transfer(bob, 200 ether);
        vm.startPrank(bob);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 5_000, abi.encode(bob));
        vm.stopPrank();
        Message memory msgBob = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msgAlice, _sign(msgAlice, wrappedBridge));
        wrappedBridge.mint(msgBob, _sign(msgBob, wrappedBridge));

        // Both claims registered independently and fully backed
        assertEq(stakeOnArrival.claimableRefund(alice), 99.7 ether);
        assertEq(stakeOnArrival.claimableRefund(bob), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 199.4 ether);

        // Alice claims hers
        vm.prank(alice);
        stakeOnArrival.claimRefund(alice);
        assertEq(wrappedToken.balanceOf(alice), 99.7 ether);
        assertEq(stakeOnArrival.claimableRefund(alice), 0);
        assertEq(stakeOnArrival.claimableRefund(bob), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 99.7 ether);

        // Bob claims his
        vm.prank(bob);
        stakeOnArrival.claimRefund(bob);
        assertEq(wrappedToken.balanceOf(bob), 99.7 ether);
        assertEq(stakeOnArrival.claimableRefund(bob), 0);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 22: Subsequent partial cap staking preserves outstanding claims
    function test_StakeOnArrival_SubsequentPartialCap_PreservesOutstandingClaim() public {
        // Alice has an outstanding claim
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 5_000, abi.encode(alice));
        vm.stopPrank();
        Message memory msgAlice = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msgAlice, _sign(msgAlice, wrappedBridge));
        assertEq(stakeOnArrival.claimableRefund(alice), 99.7 ether);

        // Set staking cap to 30 ether for Bob's operation
        vm.prank(admin);
        staking.setDepositCap(0, 30 ether);

        // Bob bridges with full hook gas
        vm.chainId(CHAIN_A);
        vm.prank(admin);
        token.transfer(bob, 200 ether);
        vm.startPrank(bob);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 500_000, abi.encode(bob));
        vm.stopPrank();
        Message memory msgBob = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msgBob, _sign(msgBob, wrappedBridge));

        // Bob got 30 ether staked and 69.7 ether refunded directly
        assertEq(staking.stakedAmount(0, bob), 30 ether);
        assertEq(wrappedToken.balanceOf(bob), 69.7 ether);

        // Alice's 99.7 ether claim was NOT touched or diluted
        assertEq(stakeOnArrival.claimableRefund(alice), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 99.7 ether);

        // Alice claims her refund
        vm.prank(alice);
        stakeOnArrival.claimRefund(alice);
        assertEq(wrappedToken.balanceOf(alice), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 23: Beneficiary encodings (truncated and zero address)
    function test_StakeOnArrival_BeneficiaryEncodings_AllVariants() public {
        // 1. Truncated 4 bytes
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 500_000, hex"1234");
        vm.stopPrank();
        Message memory msg1 = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msg1, _sign(msg1, wrappedBridge));
        assertGt(staking.stakedAmount(0, alice), 0);

        // 2. Encoded address(0)
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 500_000, abi.encode(address(0)));
        vm.stopPrank();
        Message memory msg2 = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msg2, _sign(msg2, wrappedBridge));
        // Falls back to alice and stakes for alice
        assertGt(staking.stakedAmount(0, alice), 99.7 ether);
    }

    /// Scenario 24: Zero sender message reverts
    function test_WrappedBridge_ZeroSender_Reverts() public {
        Message memory zeroSenderMsg = Message({
            srcChainId: CHAIN_A,
            dstChainId: CHAIN_B,
            nonce: 999,
            sender: address(0),
            recipient: alice,
            amount: 50 ether,
            hookGasLimit: 0,
            hookData: ""
        });

        bytes[] memory sigs = _sign(zeroSenderMsg, wrappedBridge);

        vm.chainId(CHAIN_B);
        vm.expectRevert("zero sender");
        wrappedBridge.mint(zeroSenderMsg, sigs);
    }

    /// Scenario 25: Realistic relayer gas limits
    function test_WrappedBridge_RealisticRelayerGasSettings() public {
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 5_000, abi.encode(alice));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        // Minting executes with 300,000 gas limit (typical production relayer gas allocation)
        wrappedBridge.mint{gas: 300_000}(msgSent, _sign(msgSent, wrappedBridge));

        assertEq(stakeOnArrival.claimableRefund(alice), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 99.7 ether);
    }

    /// Scenario 26 (SEC-01 Test 1): Requested hook reverts, then onHookFailure attempts to consume all forwarded gas
    function test_SEC01_RequestedHookReverts_FailureCallbackGasIsBounded() public {
        RevertingHookGasBurningFailureReceiver badReceiver = new RevertingHookGasBurningFailureReceiver();

        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(badReceiver), 100 ether, 50_000, abi.encode(alice));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        bytes[] memory sigs = _sign(msgSent, wrappedBridge);
        bytes32 digest = wrappedBridge.messageDigest(msgSent);

        // Relayer submits mint with 5,000,000 gas.
        // onBridgeReceived reverts, then onHookFailure attempts while(true){} gas burn.
        // HOOK_FAILURE_GAS_CAP caps forwarded gas to 50,000, so the malicious contract cannot burn 5M gas.
        // onHookFailure reverts/OOGs, causing mint to revert atomically.
        uint256 gasBefore = gasleft();
        vm.expectRevert();
        wrappedBridge.mint{gas: 5_000_000}(msgSent, sigs);
        uint256 gasUsed = gasBefore - gasleft();

        // Relayer gas burned is strictly bounded (< 300,000 gas, NOT 5,000,000 gas!)
        assertLt(gasUsed, 300_000);

        // Token minting and replay protection rolled back atomically
        assertFalse(wrappedBridge.isMessageExecuted(digest));
        assertEq(wrappedToken.balanceOf(address(badReceiver)), 0);
    }

    /// Scenario 27 (SEC-01 Test 2): Requested hook runs out of gas, then failure notification succeeds for StakeOnArrival
    function test_SEC01_RequestedHookOOG_StakeOnArrivalRecoverySucceeds() public {
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 5_000, abi.encode(alice));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        bytes[] memory sigs = _sign(msgSent, wrappedBridge);
        bytes32 digest = wrappedBridge.messageDigest(msgSent);

        // Relayer mints with realistic gas
        wrappedBridge.mint{gas: 300_000}(msgSent, sigs);

        // Hook ran out of gas, failure notification succeeded, claim registered for alice
        assertTrue(wrappedBridge.isMessageExecuted(digest));
        assertEq(stakeOnArrival.claimableRefund(alice), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 99.7 ether);

        // Beneficiary can safely claim 100% of the refund
        vm.prank(alice);
        stakeOnArrival.claimRefund(alice);
        assertEq(wrappedToken.balanceOf(alice), 99.7 ether);
        assertEq(stakeOnArrival.claimableRefund(alice), 0);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 28 (SEC-01 Test 3): Failure notification itself runs out of gas and mint reverts atomically
    function test_SEC01_FailureNotificationOOG_MintRevertsAtomically() public {
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 5_000, abi.encode(alice));
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        bytes[] memory sigs = _sign(msgSent, wrappedBridge);
        bytes32 digest = wrappedBridge.messageDigest(msgSent);

        // Submit mint with insufficient gas for onHookFailure to complete
        vm.expectRevert();
        wrappedBridge.mint{gas: 110_000}(msgSent, sigs);

        // Reverted atomically: replay protection NOT set, no tokens minted, no claim registered
        assertFalse(wrappedBridge.isMessageExecuted(digest));
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
        assertEq(stakeOnArrival.claimableRefund(alice), 0);

        // Retry with sufficient gas succeeds completely
        wrappedBridge.mint(msgSent, sigs);
        assertTrue(wrappedBridge.isMessageExecuted(digest));
        assertEq(stakeOnArrival.claimableRefund(alice), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 99.7 ether);
    }

    /// Scenario 29 (SEC-01 Test 4): Unhooked malicious receiver attempts gas exhaustion in both callbacks
    function test_SEC01_UnhookedMaliciousReceiver_GasExhaustionBounded() public {
        GasConsumingRecipient gasBurner = new GasConsumingRecipient();

        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        // Unhooked transfer to a recipient that loops while(true){} in both onBridgeReceived and onHookFailure
        nativeBridge.lock(CHAIN_B, address(gasBurner), 100 ether);
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();
        assertEq(msgSent.hookGasLimit, 0);
        assertEq(msgSent.hookData.length, 0);

        vm.chainId(CHAIN_B);
        bytes[] memory sigs = _sign(msgSent, wrappedBridge);
        bytes32 digest = wrappedBridge.messageDigest(msgSent);

        // Relayer submits mint with 5,000,000 gas
        // Gas burned in onBridgeReceived is capped at UNHOOKED_GAS_CAP (350k).
        // Gas burned in onHookFailure is capped at HOOK_FAILURE_GAS_CAP (50k).
        uint256 gasBefore = gasleft();
        wrappedBridge.mint{gas: 5_000_000}(msgSent, sigs);
        uint256 gasUsed = gasBefore - gasleft();

        // Exact isolated relayer call gas measurement: ~485k gas (strictly bounded below 600,000 gas)
        // Over 4,400,000 gas is preserved and refunded to relayer!
        assertLt(gasUsed, 600_000);

        // Ordinary transfer succeeded and tokens delivered to intended recipient
        assertEq(wrappedToken.balanceOf(address(gasBurner)), 99.7 ether);
        assertTrue(wrappedBridge.isMessageExecuted(digest));
    }

    /// Scenario 30 (SEC-01 Test 5): Normal contract-wallet transfer still succeeds
    function test_SEC01_NormalContractWallet_TransferSucceeds() public {
        StrictContractWallet wallet = new StrictContractWallet();

        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lock(CHAIN_B, address(wallet), 100 ether);
        vm.stopPrank();

        Message memory msgSent = _getLastMessage();

        vm.chainId(CHAIN_B);
        bytes[] memory sigs = _sign(msgSent, wrappedBridge);
        bytes32 digest = wrappedBridge.messageDigest(msgSent);

        // Wallet reverts on unexpected selectors, but unhooked mint safely catches and completes
        wrappedBridge.mint(msgSent, sigs);

        assertEq(wrappedToken.balanceOf(address(wallet)), 99.7 ether);
        assertTrue(wrappedBridge.isMessageExecuted(digest));
    }

    /// Scenario 31 (SEC-01 Test 6): Normal unhooked transfer to StakeOnArrival still stakes or registers a backed refund
    function test_SEC01_StakeOnArrival_NoHook_SuccessAndRefund() public {
        // Case A: Pool has capacity -> unhooked transfer to StakeOnArrival stakes for sender (alice)
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lock(CHAIN_B, address(stakeOnArrival), 100 ether);
        vm.stopPrank();

        Message memory msgA = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msgA, _sign(msgA, wrappedBridge));

        // Automatically staked for sender (alice)
        assertEq(staking.stakedAmount(0, alice), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);

        // Case B: Staking deposit fails (pool cap reached) -> refunds wHBR directly to sender
        vm.prank(admin);
        staking.setDepositCap(0, 99.7 ether);

        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lock(CHAIN_B, address(stakeOnArrival), 100 ether);
        vm.stopPrank();

        Message memory msgB = _getLastMessage();

        vm.chainId(CHAIN_B);
        wrappedBridge.mint(msgB, _sign(msgB, wrappedBridge));

        // Alice receives 99.7 ether wHBR refund directly
        assertEq(wrappedToken.balanceOf(alice), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);

        // Case C: Gas is constrained so onBridgeReceived OOGs -> onHookFailure registers backed refund claim
        vm.prank(admin);
        staking.setDepositCap(0, 1_000 ether); // re-enable capacity

        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lock(CHAIN_B, address(stakeOnArrival), 100 ether);
        vm.stopPrank();

        Message memory msgC = _getLastMessage();

        vm.chainId(CHAIN_B);
        // Mint with constrained gas insufficient for full staking.deposit (~200k needed), but enough for mint + onHookFailure
        wrappedBridge.mint{gas: 200_000}(msgC, _sign(msgC, wrappedBridge));

        // Claim is registered for alice
        assertEq(stakeOnArrival.claimableRefund(alice), 99.7 ether);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 99.7 ether);

        // Alice claims her refund
        vm.prank(alice);
        stakeOnArrival.claimRefund(alice);
        assertEq(wrappedToken.balanceOf(alice), 199.4 ether); // 99.7 from Case B + 99.7 from Case C
        assertEq(stakeOnArrival.claimableRefund(alice), 0);
        assertEq(wrappedToken.balanceOf(address(stakeOnArrival)), 0);
    }

    /// Scenario 32 (SEC-01 Test 7): Replay protection remains correct after both successful recovery and atomic rollback
    function test_SEC01_ReplayProtection_AfterRecoveryAndRollback() public {
        // Path A: Atomic Rollback does NOT consume replay protection
        RevertingHookGasBurningFailureReceiver badReceiver = new RevertingHookGasBurningFailureReceiver();

        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(badReceiver), 100 ether, 50_000, abi.encode(alice));
        vm.stopPrank();

        Message memory rollbackMsg = _getLastMessage();

        vm.chainId(CHAIN_B);
        bytes[] memory rollbackSigs = _sign(rollbackMsg, wrappedBridge);
        bytes32 rollbackDigest = wrappedBridge.messageDigest(rollbackMsg);

        // Initial submission fails and rolls back atomically
        vm.expectRevert();
        wrappedBridge.mint(rollbackMsg, rollbackSigs);
        assertFalse(wrappedBridge.isMessageExecuted(rollbackDigest));

        // Path B: Successful recovery DOES consume replay protection
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.recordLogs();
        nativeBridge.lockWithHook(CHAIN_B, address(stakeOnArrival), 100 ether, 5_000, abi.encode(alice));
        vm.stopPrank();

        Message memory recoveryMsg = _getLastMessage();

        vm.chainId(CHAIN_B);
        bytes[] memory recoverySigs = _sign(recoveryMsg, wrappedBridge);
        bytes32 recoveryDigest = wrappedBridge.messageDigest(recoveryMsg);

        // Successful recovery marks message executed
        wrappedBridge.mint{gas: 300_000}(recoveryMsg, recoverySigs);
        assertTrue(wrappedBridge.isMessageExecuted(recoveryDigest));
        assertEq(stakeOnArrival.claimableRefund(alice), 99.7 ether);

        // Duplicate replay of the recovery message reverts immediately
        vm.expectRevert("message already executed");
        wrappedBridge.mint(recoveryMsg, recoverySigs);
    }

    // ───────── helpers ─────────

    function _createValidators(uint256 count) internal {
        for (uint256 index; index < count; index++) {
            uint256 key = uint256(keccak256(abi.encode("validator", index)));
            validatorKeys.push(key);
            validatorAddresses.push(vm.addr(key));
        }
        for (uint256 outer = 1; outer < count; outer++) {
            for (uint256 inner = outer; inner > 0 && validatorAddresses[inner - 1] > validatorAddresses[inner]; inner--) {
                (validatorAddresses[inner - 1], validatorAddresses[inner]) =
                    (validatorAddresses[inner], validatorAddresses[inner - 1]);
                (validatorKeys[inner - 1], validatorKeys[inner]) = (validatorKeys[inner], validatorKeys[inner - 1]);
            }
        }
    }

    function _getLastMessage() internal returns (Message memory message) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("MessageSent(bytes32,(uint256,uint256,uint256,address,address,uint256,uint256,bytes))");
        for (uint256 i = logs.length; i > 0; i--) {
            if (logs[i - 1].topics.length > 0 && logs[i - 1].topics[0] == topic) {
                return abi.decode(logs[i - 1].data, (Message));
            }
        }
        revert("no MessageSent log");
    }

    function _sign(Message memory message, WrappedBridge destinationBridge)
        internal
        view
        returns (bytes[] memory signatures)
    {
        bytes32 digest = destinationBridge.messageDigest(message);
        signatures = new bytes[](THRESHOLD);
        for (uint256 index; index < THRESHOLD; index++) {
            (uint8 sigV, bytes32 sigR, bytes32 sigS) = vm.sign(validatorKeys[index], digest);
            signatures[index] = abi.encodePacked(sigR, sigS, sigV);
        }
    }
}
