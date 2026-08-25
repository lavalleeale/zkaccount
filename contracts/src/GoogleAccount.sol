// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IEntryPoint, PackedUserOperation} from "./interfaces/IEntryPoint.sol";
import {GoogleJWTValidator} from "./GoogleJWTValidator.sol";

contract GoogleAccount {
    uint8 public constant SIGNATURE_DEVICE = 0;
    uint8 public constant SIGNATURE_GOOGLE = 1;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;
    uint256 internal constant SECP256K1N_HALF =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    error OnlyEntryPoint();
    error OnlySelf();
    error CallFailed(bytes reason);
    error InvalidGoogleCallData();
    error InvalidSignatureEncoding();
    error ZeroAddress();

    bytes32 public immutable identity;
    IEntryPoint public immutable entryPoint;
    GoogleJWTValidator public immutable googleValidator;
    address public immutable factory;

    mapping(address device => bool enabled) public deviceKeys;
    mapping(bytes32 audience => bool enabled) public allowedAudiences;

    event DeviceSet(address indexed device, bool enabled);
    event AudienceSet(bytes32 indexed audience, bool enabled);
    event Executed(address indexed target, uint256 value, bytes data);

    constructor(
        bytes32 identity_,
        IEntryPoint entryPoint_,
        GoogleJWTValidator googleValidator_,
        address factory_,
        bytes32 rootAudience
    ) {
        if (address(entryPoint_) == address(0) || address(googleValidator_) == address(0) || factory_ == address(0)) {
            revert ZeroAddress();
        }
        identity = identity_;
        entryPoint = entryPoint_;
        googleValidator = googleValidator_;
        factory = factory_;
        allowedAudiences[rootAudience] = true;
        emit AudienceSet(rootAudience, true);
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

    function addAudience(bytes32 audience) external onlySelf {
        allowedAudiences[audience] = true;
        emit AudienceSet(audience, true);
    }

    function removeAudience(bytes32 audience) external onlySelf {
        allowedAudiences[audience] = false;
        emit AudienceSet(audience, false);
    }

    function addDevice(address device) external onlySelf {
        if (device == address(0)) revert ZeroAddress();
        deviceKeys[device] = true;
        emit DeviceSet(device, true);
    }

    function removeDevice(address device) external onlySelf {
        deviceKeys[device] = false;
        emit DeviceSet(device, false);
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        bytes calldata signature = userOp.signature;
        if (signature.length == 0) return SIG_VALIDATION_FAILED;

        uint8 mode = uint8(signature[0]);
        if (mode == SIGNATURE_DEVICE) {
            validationData = _validateDevice(userOpHash, signature[1:]);
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

    function _validateDevice(bytes32 userOpHash, bytes calldata signature) internal view returns (uint256) {
        if (signature.length != 65) return SIG_VALIDATION_FAILED;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return SIG_VALIDATION_FAILED;
        if (uint256(s) == 0 || uint256(s) > SECP256K1N_HALF) return SIG_VALIDATION_FAILED;
        address signer = ecrecover(userOpHash, v, r, s);
        return signer != address(0) && deviceKeys[signer] ? 0 : SIG_VALIDATION_FAILED;
    }

    function _validateGoogle(bytes calldata callData, bytes calldata encodedAuthorization) internal view returns (uint256) {
        (bytes memory proof, bytes32[] memory publicInputs) = abi.decode(encodedAuthorization, (bytes, bytes32[]));
        GoogleJWTValidator.GoogleAuthorization memory auth =
            googleValidator.verifyGoogleAuthorization(address(this), proof, publicInputs);
        if (!_isAddDeviceCall(callData, auth.deviceKey)) revert InvalidGoogleCallData();
        // The proof is intentionally not persisted. Once its bound device has
        // been installed, reject later UserOperations that reuse the same
        // public proof with a fresh EntryPoint nonce.
        if (deviceKeys[auth.deviceKey]) return SIG_VALIDATION_FAILED;
        return _packValidationData(auth.validUntil);
    }

    function _isAddDeviceCall(bytes calldata callData, address device) internal view returns (bool) {
        bytes memory inner = abi.encodeCall(this.addDevice, (device));
        bytes memory expected = abi.encodeCall(this.execute, (address(this), 0, inner));
        return keccak256(callData) == keccak256(expected);
    }

    function _packValidationData(uint48 validUntil) internal pure returns (uint256) {
        return uint256(validUntil) << 160;
    }
}
