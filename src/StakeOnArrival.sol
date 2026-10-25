// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IStakeOnArrival} from "./interfaces/IStakeOnArrival.sol";
import {IHarborStaking} from "./interfaces/IHarborStaking.sol";

/// @notice Interface for receiving notification of hook execution failure from WrappedBridge.
interface IHookFailureReceiver {
    function onHookFailure(address sender, uint256 amount, bytes calldata hookData) external;
}

/// @title StakeOnArrival
/// @notice Hook receiver contract on Chain B that receives minted wHBR from WrappedBridge
///         and deposits it into HarborStaking for the designated beneficiary.
///         Guarantees that if staking is not possible or only partially possible,
///         the user still receives their wHBR and never loses funds.
contract StakeOnArrival is IStakeOnArrival, IHookFailureReceiver, ReentrancyGuard {
    using SafeERC20 for IERC20;

    address public immutable bridge;
    IERC20 public immutable wrappedToken;
    IHarborStaking public immutable staking;
    uint256 public immutable pid;

    mapping(address => uint256) public claimableRefund;

    event BridgeAndStakeSucceeded(address indexed beneficiary, uint256 stakedAmount);
    event BridgeAndStakePartial(address indexed beneficiary, uint256 stakedAmount, uint256 refundedAmount);
    event BridgeAndStakeFailed(address indexed beneficiary, uint256 refundedAmount, string reason);
    event RefundRegistered(address indexed beneficiary, uint256 amount);
    event RefundClaimed(address indexed beneficiary, uint256 amount);

    modifier onlyBridge() {
        require(msg.sender == bridge, "only bridge");
        _;
    }

    constructor(address bridge_, address wrappedToken_, address staking_, uint256 pid_) {
        require(bridge_ != address(0), "zero bridge");
        require(wrappedToken_ != address(0), "zero wrapped token");
        require(staking_ != address(0), "zero staking");

        bridge = bridge_;
        wrappedToken = IERC20(wrappedToken_);
        staking = IHarborStaking(staking_);
        pid = pid_;
    }

    function onBridgeReceived(
        uint256, /* srcChainId */
        address sender,
        uint256 amount,
        bytes calldata hookData
    ) external override onlyBridge nonReentrant {
        address beneficiary = _decodeBeneficiary(sender, hookData);
        if (beneficiary == address(0)) {
            return;
        }

        // If beneficiary is a contract, HarborStaking attributes deposit to msg.sender (this contract),
        // which prevents the beneficiary from ever withdrawing.
        // Therefore, we refund directly to the contract beneficiary without staking.
        if (beneficiary.code.length > 0) {
            wrappedToken.safeTransfer(beneficiary, amount);
            emit BridgeAndStakeFailed(beneficiary, amount, "contract beneficiary");
            return;
        }

        // Attempt deposit into HarborStaking
        wrappedToken.forceApprove(address(staking), amount);
        uint256 balanceBefore = wrappedToken.balanceOf(address(this));

        try staking.deposit(pid, amount, beneficiary) {
            uint256 balanceAfter = wrappedToken.balanceOf(address(this));
            uint256 spent = balanceBefore > balanceAfter ? balanceBefore - balanceAfter : 0;

            if (spent < amount) {
                // Deposit cap was hit and only partial deposit was accepted
                uint256 unspent = amount - spent;
                wrappedToken.safeTransfer(beneficiary, unspent);
                emit BridgeAndStakePartial(beneficiary, spent, unspent);
            } else {
                emit BridgeAndStakeSucceeded(beneficiary, spent);
            }

            // Forward any staking rewards distributed to this contract during deposit
            uint256 rewards = balanceAfter > (balanceBefore - spent) ? balanceAfter - (balanceBefore - spent) : 0;
            if (rewards > 0) {
                wrappedToken.safeTransfer(beneficiary, rewards);
            }
        } catch {
            // Staking deposit failed (e.g. pool full, operator not set, invalid pid, etc.)
            // Reset approval and refund full amount to beneficiary
            wrappedToken.forceApprove(address(staking), 0);
            wrappedToken.safeTransfer(beneficiary, amount);
            emit BridgeAndStakeFailed(beneficiary, amount, "staking deposit failed");
        }
    }

    /// @notice Called by WrappedBridge when onBridgeReceived fails (e.g. out of gas)
    ///         or when an unhooked transfer is directed to StakeOnArrival.
    ///         Performs bounded claim registration and event emission with no external token transfers.
    function onHookFailure(
        address sender,
        uint256 amount,
        bytes calldata hookData
    ) external override onlyBridge nonReentrant {
        address beneficiary = _decodeBeneficiary(sender, hookData);
        if (beneficiary == address(0)) {
            return;
        }

        claimableRefund[beneficiary] += amount;
        emit RefundRegistered(beneficiary, amount);
    }

    /// @notice Allows a beneficiary (or any caller on their behalf) to claim registered refunds.
    ///         Tokens are strictly sent to the designated beneficiary.
    function claimRefund(address beneficiary) external nonReentrant {
        require(beneficiary != address(0), "zero beneficiary");
        uint256 amount = claimableRefund[beneficiary];
        require(amount > 0, "no claimable refund");

        claimableRefund[beneficiary] = 0;
        wrappedToken.safeTransfer(beneficiary, amount);
        emit RefundClaimed(beneficiary, amount);
    }

    function _decodeBeneficiary(address sender, bytes calldata hookData) internal pure returns (address) {
        address beneficiary = address(0);
        if (hookData.length >= 32) {
            bytes32 word;
            assembly {
                word := calldataload(hookData.offset)
            }
            if (uint256(word) >> 160 == 0) {
                beneficiary = address(uint160(uint256(word)));
            }
        }
        if (beneficiary == address(0)) {
            beneficiary = sender;
        }
        return beneficiary;
    }
}
