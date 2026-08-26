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

    mapping(address device => WebAuthnDevice credential) public webAuthnDevices;
    uint64 public googleNonce;

    event DeviceSet(address indexed device, bool enabled, string rpId);
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
        webAuthnDevices[device] = WebAuthnDevice(qx, qy, rpIdHash, true);
        emit DeviceSet(device, true, rpId);
    }

    function removeDevice(address device) external onlySelf {
        delete webAuthnDevices[device];
        emit DeviceSet(device, false, "");
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
        uint8 actionAddDevice = googleValidator.ACTION_ADD_DEVICE();
        uint8 actionRemoveDevice = googleValidator.ACTION_REMOVE_DEVICE();
        if (auth.action == actionAddDevice) {
            if (!_isAddDeviceCall(callData, auth.deviceKey, qx, qy, rpId)) revert InvalidGoogleCallData();
        } else if (auth.action == actionRemoveDevice) {
            if (!_isRemoveDeviceCall(callData, auth.deviceKey, qx, qy, rpId)) revert InvalidGoogleCallData();
        } else revert InvalidGoogleCallData();
        // An already-installed device needs no second bootstrap. The monotonic
        // Google nonce below permanently rejects the proof even after removal.
        if (auth.action == actionAddDevice && webAuthnDevices[auth.deviceKey].enabled) return SIG_VALIDATION_FAILED;
        if (auth.action == actionRemoveDevice && !webAuthnDevices[auth.deviceKey].enabled) return SIG_VALIDATION_FAILED;
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
        bytes memory inner = abi.encodeCall(this.addDevice, (device, qx, qy, rpId));
        bytes memory expected = abi.encodeCall(this.execute, (address(this), 0, inner));
        return keccak256(callData) == keccak256(expected);
    }

    function _isRemoveDeviceCall(bytes calldata callData, address device, bytes32 qx, bytes32 qy, string memory rpId)
        internal view returns (bool)
    {
        if (qx != bytes32(0) || qy != bytes32(0) || bytes(rpId).length != 0) return false;
        bytes memory inner = abi.encodeCall(this.removeDevice, (device));
        bytes memory expected = abi.encodeCall(this.execute, (address(this), 0, inner));
        return keccak256(callData) == keccak256(expected);
    }

    function _packValidationData(uint48 validUntil) internal pure returns (uint256) {
        return uint256(validUntil) << 160;
    }
}
