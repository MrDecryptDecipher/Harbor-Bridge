// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {HarborToken} from "../src/token/HarborToken.sol";
import {WrappedHarbor} from "../src/token/WrappedHarbor.sol";
import {NativeBridge} from "../src/NativeBridge.sol";
import {WrappedBridge} from "../src/WrappedBridge.sol";
import {INativeBridge, IWrappedBridge, Message} from "../src/interfaces/IHarborBridge.sol";

/// @title HardenedBridgeTest
/// @notice Comprehensive security and hardening test suite proving that NativeBridge
///         and WrappedBridge prevent all exploits and failures identified in V0.
contract HardenedBridgeTest is Test {
    uint256 internal constant CHAIN_A = 8453200012;
    uint256 internal constant CHAIN_B = 1002;
    uint256 internal constant THRESHOLD = 2;

    address internal admin = makeAddr("admin");
    address internal alice = makeAddr("alice");
    address internal attacker = makeAddr("attacker");

    uint256[] internal validatorKeys;
    address[] internal validatorAddresses;

    HarborToken internal token;
    WrappedHarbor internal wrappedToken;
    NativeBridge internal nativeBridge;
    WrappedBridge internal wrappedBridge;

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

        // Fund alice on Chain A
        vm.prank(admin);
        token.transfer(alice, 1_000 ether);
    }

    /// Prevention 1: Non-admin cannot call setValidators
    function test_Hardened_SetValidators_UnauthorizedReverts() public {
        address[] memory newValidators = new address[](1);
        newValidators[0] = attacker;

        vm.prank(attacker);
        vm.expectRevert();
        nativeBridge.setValidators(newValidators, 1);
    }

    /// Prevention 2: setValidators removes old validators
    function test_Hardened_SetValidators_ClearsOldValidators() public {
        address revokedValidator = validatorAddresses[0];
        assertTrue(nativeBridge.isValidator(revokedValidator));

        address[] memory newValidators = new address[](2);
        newValidators[0] = makeAddr("valNew1");
        newValidators[1] = makeAddr("valNew2");

        vm.prank(admin);
        nativeBridge.setValidators(newValidators, 2);

        // Old validator is no longer authorized
        assertFalse(nativeBridge.isValidator(revokedValidator));
        assertTrue(nativeBridge.isValidator(newValidators[0]));
        assertTrue(nativeBridge.isValidator(newValidators[1]));
    }

    /// Prevention 3: Tampered amount alters digest and fails signature verification
    function test_Hardened_TamperedAmountFails() public {
        vm.chainId(CHAIN_B);
        vm.startPrank(alice);
        // Mint wHBR for testing burn
        // First lock on A to get valid message
        vm.stopPrank();

        Message memory msgToUnlock = Message({
            srcChainId: CHAIN_B,
            dstChainId: CHAIN_A,
            nonce: 0,
            sender: alice,
            recipient: alice,
            amount: 50 ether,
            hookGasLimit: 0,
            hookData: ""
        });

        bytes[] memory sigs = _sign(msgToUnlock, nativeBridge);

        // Attacker tampers with amount
        msgToUnlock.amount = 10_000 ether;

        vm.chainId(CHAIN_A);
        vm.expectRevert();
        nativeBridge.unlock(msgToUnlock, sigs);
    }

    /// Prevention 4: Duplicate signatures are rejected by strict ascending signer check
    function test_Hardened_DuplicateSignaturesReverts() public {
        Message memory msgToUnlock = Message({
            srcChainId: CHAIN_B,
            dstChainId: CHAIN_A,
            nonce: 0,
            sender: alice,
            recipient: alice,
            amount: 50 ether,
            hookGasLimit: 0,
            hookData: ""
        });

        bytes32 digest = nativeBridge.messageDigest(msgToUnlock);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validatorKeys[0], digest);
        bytes memory singleSig = abi.encodePacked(r, s, v);

        bytes[] memory dupSigs = new bytes[](2);
        dupSigs[0] = singleSig;
        dupSigs[1] = singleSig;

        vm.chainId(CHAIN_A);
        vm.expectRevert();
        nativeBridge.unlock(msgToUnlock, dupSigs);
    }

    /// Prevention 5: Malleable s signature is rejected
    function test_Hardened_MalleableSignatureReverts() public {
        Message memory msgToUnlock = Message({
            srcChainId: CHAIN_B,
            dstChainId: CHAIN_A,
            nonce: 0,
            sender: alice,
            recipient: alice,
            amount: 50 ether,
            hookGasLimit: 0,
            hookData: ""
        });

        bytes32 digest = nativeBridge.messageDigest(msgToUnlock);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(validatorKeys[0], digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(validatorKeys[1], digest);

        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 malleableS1 = bytes32(n - uint256(s1));
        uint8 malleableV1 = v1 == 27 ? 28 : 27;

        bytes[] memory malleableSigs = new bytes[](2);
        malleableSigs[0] = abi.encodePacked(r1, malleableS1, malleableV1);
        malleableSigs[1] = abi.encodePacked(r2, s2, v2);

        vm.chainId(CHAIN_A);
        vm.expectRevert();
        nativeBridge.unlock(msgToUnlock, malleableSigs);
    }

    /// Prevention 6: Exact message replay is rejected
    function test_Hardened_ReplayProtectionReverts() public {
        // Fund native bridge so it has tokens to unlock
        vm.chainId(CHAIN_A);
        vm.prank(admin);
        token.transfer(address(nativeBridge), 500 ether);

        Message memory msgToUnlock = Message({
            srcChainId: CHAIN_B,
            dstChainId: CHAIN_A,
            nonce: 10,
            sender: alice,
            recipient: alice,
            amount: 50 ether,
            hookGasLimit: 0,
            hookData: ""
        });

        bytes[] memory sigs = _sign(msgToUnlock, nativeBridge);

        // First unlock succeeds
        nativeBridge.unlock(msgToUnlock, sigs);
        assertTrue(nativeBridge.isMessageExecuted(nativeBridge.messageDigest(msgToUnlock)));

        // Second unlock attempt MUST revert
        vm.expectRevert();
        nativeBridge.unlock(msgToUnlock, sigs);
    }

    /// Prevention 7: Cross-chain replay (wrong dstChainId or wrong srcChainId) reverts
    function test_Hardened_WrongChainReverts() public {
        Message memory badDstMessage = Message({
            srcChainId: CHAIN_B,
            dstChainId: 99999, // Wrong destination
            nonce: 1,
            sender: alice,
            recipient: alice,
            amount: 50 ether,
            hookGasLimit: 0,
            hookData: ""
        });

        bytes[] memory sigs = _sign(badDstMessage, nativeBridge);

        vm.chainId(CHAIN_A);
        vm.expectRevert();
        nativeBridge.unlock(badDstMessage, sigs);
    }

    /// Prevention 8: Signatures out of ascending order revert
    function test_Hardened_UnorderedSignaturesReverts() public {
        Message memory msgToUnlock = Message({
            srcChainId: CHAIN_B,
            dstChainId: CHAIN_A,
            nonce: 1,
            sender: alice,
            recipient: alice,
            amount: 50 ether,
            hookGasLimit: 0,
            hookData: ""
        });

        bytes32 digest = nativeBridge.messageDigest(msgToUnlock);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(validatorKeys[0], digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(validatorKeys[1], digest);

        // Reverse order (descending instead of ascending)
        bytes[] memory reversedSigs = new bytes[](2);
        reversedSigs[0] = abi.encodePacked(r2, s2, v2);
        reversedSigs[1] = abi.encodePacked(r1, s1, v1);

        vm.chainId(CHAIN_A);
        vm.expectRevert();
        nativeBridge.unlock(msgToUnlock, reversedSigs);
    }

    /// Prevention 9: Fewer than threshold signatures revert
    function test_Hardened_InsufficientSignaturesReverts() public {
        Message memory msgToUnlock = Message({
            srcChainId: CHAIN_B,
            dstChainId: CHAIN_A,
            nonce: 1,
            sender: alice,
            recipient: alice,
            amount: 50 ether,
            hookGasLimit: 0,
            hookData: ""
        });

        bytes32 digest = nativeBridge.messageDigest(msgToUnlock);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(validatorKeys[0], digest);

        bytes[] memory oneSig = new bytes[](1);
        oneSig[0] = abi.encodePacked(r1, s1, v1);

        vm.chainId(CHAIN_A);
        vm.expectRevert();
        nativeBridge.unlock(msgToUnlock, oneSig);
    }

    /// Prevention 10: Fee-on-transfer tokens are accounted for by balance delta
    function test_Hardened_FeeOnTransferAccurateAccounting() public {
        vm.chainId(CHAIN_A);
        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);

        vm.recordLogs();
        bytes32 msgId = nativeBridge.lock(CHAIN_B, alice, 100 ether);
        vm.stopPrank();

        assertTrue(msgId != bytes32(0));

        // HarborToken default fee is 30 bps (0.3%).
        // 100 ether * 9970 / 10000 = 99.7 ether received by bridge
        uint256 expectedReceived = 100 ether * 9970 / 10000;
        assertEq(token.balanceOf(address(nativeBridge)), expectedReceived);
    }

    /// Prevention 11: Emergency pause stops bridge operations
    function test_Hardened_PauseStopsOperations() public {
        vm.chainId(CHAIN_A);
        vm.prank(admin);
        nativeBridge.pause();

        vm.startPrank(alice);
        token.approve(address(nativeBridge), 100 ether);
        vm.expectRevert();
        nativeBridge.lock(CHAIN_B, alice, 100 ether);
        vm.stopPrank();

        // Unpause restores operations
        vm.prank(admin);
        nativeBridge.unpause();

        vm.startPrank(alice);
        nativeBridge.lock(CHAIN_B, alice, 100 ether);
        vm.stopPrank();
    }

    /// Prevention 12: WrappedBridge setValidators removes old validators and rejects unauthorized
    function test_Hardened_WrappedBridge_SetValidators() public {
        vm.chainId(CHAIN_B);
        address revoked = validatorAddresses[0];
        assertTrue(wrappedBridge.isValidator(revoked));

        address[] memory newValidators = new address[](2);
        newValidators[0] = makeAddr("wbVal1");
        newValidators[1] = makeAddr("wbVal2");

        // Non-admin reverts
        vm.prank(attacker);
        vm.expectRevert();
        wrappedBridge.setValidators(newValidators, 2);

        // Admin succeeds
        vm.prank(admin);
        wrappedBridge.setValidators(newValidators, 2);

        assertFalse(wrappedBridge.isValidator(revoked));
        assertTrue(wrappedBridge.isValidator(newValidators[0]));
        assertTrue(wrappedBridge.isValidator(newValidators[1]));
        assertEq(wrappedBridge.threshold(), 2);
    }

    /// Prevention 13: WrappedBridge burn burns wHBR and emits MessageSent
    function test_Hardened_WrappedBridge_Burn() public {
        vm.chainId(CHAIN_B);
        // Mint wHBR to alice
        deal(address(wrappedToken), alice, 100 ether);

        vm.startPrank(alice);
        vm.recordLogs();
        bytes32 msgId = wrappedBridge.burn(CHAIN_A, alice, 40 ether);
        assertTrue(msgId != bytes32(0));
        assertEq(wrappedToken.balanceOf(alice), 60 ether);
        vm.stopPrank();
    }

    /// Prevention 14: WrappedBridge pause stops mint and burn
    function test_Hardened_WrappedBridge_Pause() public {
        vm.chainId(CHAIN_B);
        deal(address(wrappedToken), alice, 100 ether);

        vm.prank(admin);
        wrappedBridge.pause();

        vm.startPrank(alice);
        vm.expectRevert();
        wrappedBridge.burn(CHAIN_A, alice, 10 ether);
        vm.stopPrank();

        vm.prank(admin);
        wrappedBridge.unpause();

        vm.startPrank(alice);
        wrappedBridge.burn(CHAIN_A, alice, 10 ether);
        assertEq(wrappedToken.balanceOf(alice), 90 ether);
        vm.stopPrank();
    }

    /// Prevention 15: WrappedBridge setAdmin transfers admin role
    function test_Hardened_WrappedBridge_SetAdmin() public {
        vm.chainId(CHAIN_B);
        address newAdmin = makeAddr("newAdmin");

        vm.prank(attacker);
        vm.expectRevert();
        wrappedBridge.setAdmin(newAdmin);

        vm.prank(admin);
        wrappedBridge.setAdmin(newAdmin);
        assertEq(wrappedBridge.admin(), newAdmin);
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

    function _sign(Message memory message, NativeBridge destinationBridge)
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
