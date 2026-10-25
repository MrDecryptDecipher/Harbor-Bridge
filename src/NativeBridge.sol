// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {INativeBridge, Message} from "./interfaces/IHarborBridge.sol";

/// @title NativeBridge
/// @notice Hardened Chain A bridge replacing NativeBridgeV0.
///         Users lock HBR here; validators observe MessageSent events and attest
///         to minting wHBR on Chain B. When burning wHBR on Chain B, users unlock HBR here.
contract NativeBridge is INativeBridge, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    uint256 public immutable remoteChainId;
    address public admin;
    uint256 public threshold;
    address[] public validators;
    mapping(address => bool) public isValidator;
    uint256 public nextNonce;
    mapping(bytes32 => bool) public isMessageExecuted;

    event ValidatorsUpdated(address[] newValidators, uint256 newThreshold);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);
    event Unlocked(bytes32 indexed messageDigest, address indexed recipient, uint256 amount);

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

        token = IERC20(tokenAddress);
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

    function lock(uint256 dstChainId, address recipient, uint256 amount)
        external
        override
        returns (bytes32 messageId)
    {
        return _lock(dstChainId, recipient, amount, 0, "");
    }

    function lockWithHook(
        uint256 dstChainId,
        address recipient,
        uint256 amount,
        uint256 hookGasLimit,
        bytes calldata hookData
    ) external override returns (bytes32 messageId) {
        return _lock(dstChainId, recipient, amount, hookGasLimit, hookData);
    }

    function _lock(
        uint256 dstChainId,
        address recipient,
        uint256 amount,
        uint256 hookGasLimit,
        bytes memory hookData
    ) internal nonReentrant whenNotPaused returns (bytes32 messageId) {
        require(dstChainId == remoteChainId, "invalid dstChainId");
        require(recipient != address(0), "zero recipient");
        require(amount > 0, "zero amount");

        uint256 balanceBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 receivedAmount = token.balanceOf(address(this)) - balanceBefore;
        require(receivedAmount > 0, "zero received amount");

        uint256 nonce = nextNonce++;
        Message memory message = Message({
            srcChainId: block.chainid,
            dstChainId: dstChainId,
            nonce: nonce,
            sender: msg.sender,
            recipient: recipient,
            amount: receivedAmount,
            hookGasLimit: hookGasLimit,
            hookData: hookData
        });

        messageId = computeMessageId(message);
        emit MessageSent(messageId, message);
    }

    function unlock(Message calldata message, bytes[] calldata signatures)
        external
        override
        nonReentrant
        whenNotPaused
    {
        require(message.dstChainId == block.chainid, "wrong dstChainId");
        require(message.srcChainId == remoteChainId, "wrong srcChainId");
        require(message.recipient != address(0), "zero recipient");
        require(message.amount > 0, "zero amount");

        bytes32 digest = messageDigest(message);
        require(!isMessageExecuted[digest], "message already executed");

        _verifySignatures(digest, signatures);

        isMessageExecuted[digest] = true;
        token.safeTransfer(message.recipient, message.amount);

        emit Unlocked(digest, message.recipient, message.amount);
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

            // Enforce low-s (malleability protection)
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
