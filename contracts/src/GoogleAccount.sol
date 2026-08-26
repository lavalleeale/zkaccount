// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IEntryPoint, PackedUserOperation} from "./interfaces/IEntryPoint.sol";
import {GoogleJWTValidator} from "./GoogleJWTValidator.sol";
import {NativeWebAuthn} from "./NativeWebAuthn.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";

contract GoogleAccount {
    uint8 public constant SIGNATURE_DEVICE = 0;
    uint8 public constant SIGNATURE_GOOGLE = 1;
    bytes4 public constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 public constant ERC1271_INVALID_SIGNATURE = 0xffffffff;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;
    error OnlyEntryPoint();
    error OnlySelf();
    error CallFailed(bytes reason);
    error InvalidGoogleCallData();
    error InvalidDeviceIdentifier();
    error ZeroAddress();
    error GoogleNonceNotIncreasing(uint64 provided, uint64 current);
    error NoPendingDevice();
    error TimelockNotElapsed();

    /// @notice Delay before a Google-authorized device becomes usable, giving an
    /// existing device time to notice and cancel an unauthorized addition. Only
    /// applies once the account already has a device to protect; see
    /// `queueDevice`. An existing device can waive it entirely via `approveDevice`.
    uint48 public constant DEVICE_ADD_DELAY = 2 days;

    bytes32 public immutable identity;
    IEntryPoint public immutable entryPoint;
    GoogleJWTValidator public immutable googleValidator;
    address public immutable factory;

    struct WebAuthnDevice {
        bytes32 qx;
        bytes32 qy;
        bytes32 rpIdHash;
        bool enabled;
    }

    struct PendingDevice {
        bytes32 qx;
        bytes32 qy;
        bytes32 rpIdHash;
        uint48 queuedAt;
        string rpId;
    }

    mapping(address device => WebAuthnDevice credential) public webAuthnDevices;
    mapping(address device => PendingDevice pending) public pendingDevices;
    uint256 public deviceCount;
    uint64 public googleNonce;

    event DeviceSet(address indexed device, bool enabled, string rpId);
    event DeviceQueued(address indexed device, string rpId, uint48 readyAt);
    event DevicePendingCancelled(address indexed device);
    event Executed(address indexed target, uint256 value, bytes data);

    constructor(
        bytes32 identity_,
        IEntryPoint entryPoint_,
        GoogleJWTValidator googleValidator_,
        address factory_
    ) {
        if (address(entryPoint_) == address(0) || address(googleValidator_) == address(0) || factory_ == address(0)) {
            revert ZeroAddress();
        }
        identity = identity_;
        entryPoint = entryPoint_;
        googleValidator = googleValidator_;
        factory = factory_;
    }

    receive() external payable {}

    modifier onlyEntryPoint() {
        if (msg.sender != address(entryPoint)) revert OnlyEntryPoint();
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert OnlySelf();
        _;
    }

    function execute(address target, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool ok, bytes memory result) = target.call{value: value}(data);
        if (!ok) revert CallFailed(result);
        emit Executed(target, value, data);
    }

    /// @notice Validates a WebAuthn assertion made by an authorized credential.
    /// @dev The caller supplies the final digest (EIP-191, EIP-712, or another
    /// application-specific digest) as required by ERC-1271.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        bool valid = signature.length != 0 && uint8(signature[0]) == SIGNATURE_DEVICE
            && _validateWebAuthn(hash, signature[1:]) == 0;
        return valid ? ERC1271_MAGIC_VALUE : ERC1271_INVALID_SIGNATURE;
    }

    function addDevice(address device, bytes32 qx, bytes32 qy, string calldata rpId) external onlySelf {
        bytes32 rpIdHash = sha256(bytes(rpId));
        if (device == address(0)) revert ZeroAddress();
        if (device != deviceIdentifier(qx, qy, rpIdHash)) revert InvalidDeviceIdentifier();
        if (!webAuthnDevices[device].enabled) deviceCount++;
        webAuthnDevices[device] = WebAuthnDevice(qx, qy, rpIdHash, true);
        emit DeviceSet(device, true, rpId);
    }

    function removeDevice(address device) external onlySelf {
        if (webAuthnDevices[device].enabled) deviceCount--;
        delete webAuthnDevices[device];
        emit DeviceSet(device, false, "");
    }

    /// @notice Revokes every device in one self-call. Only reachable through a
    /// device-mode (0x00) signature: Google-proof (0x01) validation binds each
    /// proof to exactly one device and rejects any other call shape.
    function removeAllDevices(address[] calldata devices) external onlySelf {
        for (uint256 i = 0; i < devices.length; i++) {
            if (webAuthnDevices[devices[i]].enabled) deviceCount--;
            delete webAuthnDevices[devices[i]];
            emit DeviceSet(devices[i], false, "");
        }
    }

    /// @notice Entry point for Google-authorized device additions (see
    /// `_isAddDeviceCall`). Bootstrapping an empty account (no device to protect
    /// or notify) enables immediately; otherwise the device is queued behind
    /// `DEVICE_ADD_DELAY` so an existing device can cancel an unrecognized
    /// addition, or approve it early via `approveDevice`.
    function queueDevice(address device, bytes32 qx, bytes32 qy, string calldata rpId) external onlySelf {
        bytes32 rpIdHash = sha256(bytes(rpId));
        if (device == address(0)) revert ZeroAddress();
        if (device != deviceIdentifier(qx, qy, rpIdHash)) revert InvalidDeviceIdentifier();
        if (deviceCount == 0) {
            webAuthnDevices[device] = WebAuthnDevice(qx, qy, rpIdHash, true);
            deviceCount++;
            emit DeviceSet(device, true, rpId);
            return;
        }
        pendingDevices[device] = PendingDevice(qx, qy, rpIdHash, uint48(block.timestamp), rpId);
        emit DeviceQueued(device, rpId, uint48(block.timestamp) + DEVICE_ADD_DELAY);
    }

    /// @notice Activates a queued device once its timelock has elapsed.
    /// Permissionless: the device was already authorized by a Google proof and
    /// given a full delay window for an existing device to cancel it, so there's
    /// nothing left to gate this on.
    function finalizeDevice(address device) external {
        PendingDevice storage pending = pendingDevices[device];
        if (pending.queuedAt == 0) revert NoPendingDevice();
        if (block.timestamp < uint256(pending.queuedAt) + DEVICE_ADD_DELAY) revert TimelockNotElapsed();
        _activatePendingDevice(device);
    }

    /// @notice Lets an already-trusted device vouch for a queued one, skipping
    /// the remaining delay entirely (e.g. approving a fresh Google sign-in on a
    /// new device from a device you're already logged in on).
    function approveDevice(address device) external onlySelf {
        if (pendingDevices[device].queuedAt == 0) revert NoPendingDevice();
        _activatePendingDevice(device);
    }

    /// @notice Vetoes a queued device before it activates.
    function cancelPendingDevice(address device) external onlySelf {
        if (pendingDevices[device].queuedAt == 0) revert NoPendingDevice();
        delete pendingDevices[device];
        emit DevicePendingCancelled(device);
    }

    function _activatePendingDevice(address device) internal {
        PendingDevice memory pending = pendingDevices[device];
        delete pendingDevices[device];
        webAuthnDevices[device] = WebAuthnDevice(pending.qx, pending.qy, pending.rpIdHash, true);
        deviceCount++;
        emit DeviceSet(device, true, pending.rpId);
    }

    function deviceKeys(address device) external view returns (bool) {
        return webAuthnDevices[device].enabled;
    }

    function deviceIdentifier(bytes32 qx, bytes32 qy, bytes32 rpIdHash) public pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(qx, qy, rpIdHash)))));
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        bytes calldata signature = userOp.signature;
        if (signature.length == 0) return SIG_VALIDATION_FAILED;

        uint8 mode = uint8(signature[0]);
        if (mode == SIGNATURE_DEVICE) {
            validationData = _validateWebAuthn(userOpHash, signature[1:]);
        } else if (mode == SIGNATURE_GOOGLE) {
            validationData = _validateGoogle(userOp.callData, signature[1:]);
        } else {
            validationData = SIG_VALIDATION_FAILED;
        }

        if (missingAccountFunds != 0) {
            (bool sent,) = payable(msg.sender).call{value: missingAccountFunds}("");
            sent;
        }
    }

    function _validateWebAuthn(bytes32 hash, bytes calldata signature) internal view returns (uint256) {
        if (signature.length < 32) return SIG_VALIDATION_FAILED;
        address device;
        assembly ("memory-safe") {
            device := calldataload(signature.offset)
        }
        WebAuthnDevice storage credential = webAuthnDevices[device];
        if (!credential.enabled) return SIG_VALIDATION_FAILED;
        (bool decoded, WebAuthn.WebAuthnAuth calldata auth) = WebAuthn.tryDecodeAuth(signature[32:]);
        if (!decoded) return SIG_VALIDATION_FAILED;
        return NativeWebAuthn.verify(hash, credential.rpIdHash, auth, credential.qx, credential.qy)
            ? 0
            : SIG_VALIDATION_FAILED;
    }

    function _validateGoogle(bytes calldata callData, bytes calldata encodedAuthorization) internal returns (uint256) {
        (bytes memory proof, bytes32[] memory publicInputs, bytes32 qx, bytes32 qy, string memory rpId) =
            abi.decode(encodedAuthorization, (bytes, bytes32[], bytes32, bytes32, string));
        GoogleJWTValidator.GoogleAuthorization memory auth =
            googleValidator.verifyGoogleAuthorization(address(this), proof, publicInputs);
        if (!_isAddDeviceCall(callData, auth.deviceKey, qx, qy, rpId)) revert InvalidGoogleCallData();
        // An already-installed device needs no second bootstrap. The monotonic
        // Google nonce below permanently rejects the proof even after removal.
        if (webAuthnDevices[auth.deviceKey].enabled) return SIG_VALIDATION_FAILED;
        uint64 currentNonce = googleNonce;
        if (auth.googleNonce <= currentNonce) {
            revert GoogleNonceNotIncreasing(auth.googleNonce, currentNonce);
        }
        // Consume the Google-issued timestamp during validation. Simulations roll
        // this write back, while the real EntryPoint call makes concurrent proofs
        // with the same or an older iat fail before execution.
        googleNonce = auth.googleNonce;
        return _packValidationData(auth.validUntil);
    }

    function _isAddDeviceCall(bytes calldata callData, address device, bytes32 qx, bytes32 qy, string memory rpId)
        internal
        view
        returns (bool)
    {
        if (device != deviceIdentifier(qx, qy, sha256(bytes(rpId)))) return false;
        bytes memory inner = abi.encodeCall(this.queueDevice, (device, qx, qy, rpId));
        bytes memory expected = abi.encodeCall(this.execute, (address(this), 0, inner));
        return keccak256(callData) == keccak256(expected);
    }

    function _packValidationData(uint48 validUntil) internal pure returns (uint256) {
        return uint256(validUntil) << 160;
    }
}
