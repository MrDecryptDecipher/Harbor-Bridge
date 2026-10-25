// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IWrappedBridge, IBridgeHookReceiver, Message} from "./interfaces/IHarborBridge.sol";
import {WrappedHarbor} from "./token/WrappedHarbor.sol";

/// @notice Interface for notifying a hook receiver when its initial execution fails.
interface IHookFailureReceiver {
    function onHookFailure(address sender, uint256 amount, bytes calldata hookData) external;
}

/// @title WrappedBridge
/// @notice Hardened Chain B bridge.
///         Mints wHBR when unlocked from Chain A, and burns wHBR to bridge back to Chain A.
///         Executes hook calls for bridge-and-stake operations.
contract WrappedBridge is IWrappedBridge, ReentrancyGuard, Pausable {
    WrappedHarbor public immutable token;
    uint256 public immutable remoteChainId;
    address public admin;
    uint256 public threshold;
    address[] public validators;
    mapping(address => bool) public isValidator;
    uint256 public nextNonce;
    mapping(bytes32 => bool) public isMessageExecuted;

    /// @notice Maximum gas forwarded to onBridgeReceived for unhooked transfers to contracts.
    ///         Calibrated to provide sufficient gas for StakeOnArrival (~180k-220k gas)
    ///         while preventing malicious contracts from consuming unbounded relayer gas.
    uint256 public constant UNHOOKED_GAS_CAP = 350_000;

    /// @notice Maximum gas forwarded to onHookFailure for failure recovery callbacks.
    ///         Sufficient for StakeOnArrival state recording (~25k gas) while bounding griefing.
    uint256 public constant HOOK_FAILURE_GAS_CAP = 50_000;

    /// @notice Backward-compatible alias for HOOK_FAILURE_GAS_CAP.
    uint256 public constant UNHOOKED_FAILURE_GAS_CAP = HOOK_FAILURE_GAS_CAP;

    /// @notice Gas reserved for the outer contract to execute catch block and failure recovery.
    uint256 public constant RESERVED_RECOVERY_GAS = 80_000;

    event ValidatorsUpdated(address[] newValidators, uint256 newThreshold);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);
    event Minted(bytes32 indexed messageDigest, address indexed recipient, uint256 amount);
    event HookExecutionFailed(bytes32 indexed messageDigest, address indexed recipient);

    modifier onlyAdmin() {
        require(msg.sender == admin, "only admin");
        _;
    }

    constructor(
        address tokenAddress,
        uint256 remoteChainId_,
        address[] memory initialValidators,
        uint256 initialThreshold,
        address adminAddress
    ) {
        require(tokenAddress != address(0), "zero token");
        require(adminAddress != address(0), "zero admin");
        require(remoteChainId_ != 0 && remoteChainId_ != block.chainid, "invalid remote chain id");
        require(initialThreshold > 0, "zero threshold");
        require(initialValidators.length >= initialThreshold, "threshold exceeds validator count");

        token = WrappedHarbor(tokenAddress);
        remoteChainId = remoteChainId_;
        admin = adminAddress;
        threshold = initialThreshold;

        for (uint256 i = 0; i < initialValidators.length; i++) {
            address val = initialValidators[i];
            require(val != address(0), "zero validator");
            require(!isValidator[val], "duplicate validator");
            isValidator[val] = true;
        }
        validators = initialValidators;
    }

    function burn(uint256 dstChainId, address recipient, uint256 amount)
        external
        override
        nonReentrant
        whenNotPaused
        returns (bytes32 messageId)
    {
        require(dstChainId == remoteChainId, "invalid dstChainId");
        require(recipient != address(0), "zero recipient");
        require(amount > 0, "zero amount");

        token.bridgeBurn(msg.sender, amount);

        uint256 nonce = nextNonce++;
        Message memory message = Message({
            srcChainId: block.chainid,
            dstChainId: dstChainId,
            nonce: nonce,
            sender: msg.sender,
            recipient: recipient,
            amount: amount,
            hookGasLimit: 0,
            hookData: ""
        });

        messageId = computeMessageId(message);
        emit MessageSent(messageId, message);
    }

    function mint(Message calldata message, bytes[] calldata signatures)
        external
        override
        nonReentrant
        whenNotPaused
    {
        require(message.dstChainId == block.chainid, "wrong dstChainId");
        require(message.srcChainId == remoteChainId, "wrong srcChainId");
        require(message.recipient != address(0), "zero recipient");
        require(message.sender != address(0), "zero sender");
        require(message.amount > 0, "zero amount");

        bytes32 digest = messageDigest(message);
        require(!isMessageExecuted[digest], "message already executed");

        _verifySignatures(digest, signatures);

        isMessageExecuted[digest] = true;
        token.bridgeMint(message.recipient, message.amount);
        emit Minted(digest, message.recipient, message.amount);

        // Execute hook if recipient is a contract
        if (message.recipient.code.length > 0) {
            bool hookRequested = (message.hookGasLimit > 0 || message.hookData.length > 0);
            uint256 gasLimit = message.hookGasLimit > 0 ? message.hookGasLimit : UNHOOKED_GAS_CAP;
            if (gasleft() > RESERVED_RECOVERY_GAS) {
                uint256 availableGas = gasleft() - RESERVED_RECOVERY_GAS;
                if (gasLimit > availableGas) {
                    gasLimit = availableGas;
                }
            } else {
                gasLimit = 0;
            }

            try IBridgeHookReceiver(message.recipient).onBridgeReceived{gas: gasLimit}(
                message.srcChainId,
                message.sender,
                message.amount,
                message.hookData
            ) {
                // Hook execution succeeded
            } catch {
                uint256 failureGas = HOOK_FAILURE_GAS_CAP;
                if (failureGas > gasleft()) {
                    failureGas = gasleft();
                }

                if (hookRequested) {
                    emit HookExecutionFailed(digest, message.recipient);

                    // Mandatory failure recovery notification for hook requests.
                    // Strictly gas-bounded: if onHookFailure reverts or runs out of gas,
                    // mint reverts atomically so the message can be retried.
                    IHookFailureReceiver(message.recipient).onHookFailure{gas: failureGas}(
                        message.sender,
                        message.amount,
                        message.hookData
                    );
                } else {
                    // Hook was not explicitly requested (normal transfer to contract).
                    // If recipient implements IHookFailureReceiver (e.g. StakeOnArrival), register claimable refund.
                    // If recipient does not implement it (e.g. smart contract wallet), silently succeed.
                    try IHookFailureReceiver(message.recipient).onHookFailure{gas: failureGas}(
                        message.sender,
                        message.amount,
                        message.hookData
                    ) {
                        emit HookExecutionFailed(digest, message.recipient);
                    } catch {}
                }
            }
        }
    }

    function setValidators(address[] calldata newValidators, uint256 newThreshold)
        external
        override
        onlyAdmin
    {
        require(newThreshold > 0, "zero threshold");
        require(newValidators.length >= newThreshold, "threshold exceeds validator count");

        for (uint256 i = 0; i < validators.length; i++) {
            isValidator[validators[i]] = false;
        }

        for (uint256 i = 0; i < newValidators.length; i++) {
            address val = newValidators[i];
            require(val != address(0), "zero validator");
            require(!isValidator[val], "duplicate validator");
            isValidator[val] = true;
        }

        validators = newValidators;
        threshold = newThreshold;

        emit ValidatorsUpdated(newValidators, newThreshold);
    }

    function setAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "zero admin");
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }

    function pause() external onlyAdmin {
        _pause();
    }

    function unpause() external onlyAdmin {
        _unpause();
    }

    function messageDigest(Message calldata message) public view override returns (bytes32) {
        return keccak256(
            abi.encode(
                address(this),
                message.srcChainId,
                message.dstChainId,
                message.nonce,
                message.sender,
                message.recipient,
                message.amount,
                message.hookGasLimit,
                keccak256(message.hookData)
            )
        );
    }

    function computeMessageId(Message memory message) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                message.srcChainId,
                message.dstChainId,
                message.nonce,
                message.sender,
                message.recipient,
                message.amount,
                message.hookGasLimit,
                keccak256(message.hookData)
            )
        );
    }

    function _verifySignatures(bytes32 digest, bytes[] calldata signatures) internal view {
        require(signatures.length >= threshold, "insufficient signatures");

        address lastSigner = address(0);
        for (uint256 i = 0; i < signatures.length; i++) {
            bytes calldata sig = signatures[i];
            require(sig.length == 65, "bad signature length");

            bytes32 r = bytes32(sig[0:32]);
            bytes32 s = bytes32(sig[32:64]);
            uint8 v = uint8(sig[64]);

            require(
                uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D57617F1A08A1E086CE6799FF3F19E0,
                "invalid signature s"
            );
            require(v == 27 || v == 28, "invalid signature v");

            address signer = ecrecover(digest, v, r, s);
            require(signer != address(0), "ecrecover failed");
            require(signer > lastSigner, "signers not sorted or duplicate");
            require(isValidator[signer], "not a validator");

            lastSigner = signer;
        }
    }
}
