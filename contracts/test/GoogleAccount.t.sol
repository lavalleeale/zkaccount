// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {GoogleAccount} from "../src/GoogleAccount.sol";
import {GoogleAccountFactory} from "../src/GoogleAccountFactory.sol";
import {GoogleJWTValidator} from "../src/GoogleJWTValidator.sol";
import {GoogleKeyRegistry} from "../src/GoogleKeyRegistry.sol";
import {IEntryPoint, PackedUserOperation} from "../src/interfaces/IEntryPoint.sol";
import {MockGoogleVerifier} from "./mocks/MockGoogleVerifier.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function expectRevert(bytes4 selector) external;
    function expectRevert(bytes calldata revertData) external;
    function warp(uint256 timestamp) external;
}

contract MockCREForwarder {
    function updateKeys(
        GoogleKeyRegistry registry,
        bytes32 workflowId,
        bytes10 workflowName,
        address workflowOwner,
        bytes32[] memory keys
    ) external {
        registry.onReport(
            abi.encodePacked(workflowId, workflowName, workflowOwner), abi.encode(keys)
        );
    }
}

contract MockEntryPoint is IEntryPoint {
    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32) {
        return keccak256(abi.encode(userOp.sender, userOp.nonce, keccak256(userOp.callData), block.chainid, address(this)));
    }

    function validate(
        GoogleAccount account,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        return account.validateUserOp(userOp, userOpHash, 0);
    }

    function execute(GoogleAccount account, address target, uint256 value, bytes calldata data) external {
        account.execute(target, value, data);
    }
}

contract GoogleAccountTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 private constant DEVICE_PRIVATE_KEY = 0xA11CE;
    bytes32 private constant IDENTITY = keccak256("google-sub-fixture");
    bytes32 private constant ROOT_AUDIENCE = keccak256("root.apps.googleusercontent.com");
    bytes32 private constant GOOGLE_KEY = keccak256("fixture-rsa-key");

    MockEntryPoint private entryPoint;
    MockGoogleVerifier private verifier;
    MockCREForwarder private creForwarder;
    GoogleKeyRegistry private registry;
    GoogleAccountFactory private factory;
    GoogleJWTValidator private validator;
    GoogleAccount private account;
    address private device;

    function setUp() public {
        entryPoint = new MockEntryPoint();
        verifier = new MockGoogleVerifier();
        creForwarder = new MockCREForwarder();
        registry = new GoogleKeyRegistry(address(this), address(creForwarder), address(this));
        factory = new GoogleAccountFactory(entryPoint, ROOT_AUDIENCE);
        validator = new GoogleJWTValidator(verifier, registry, address(factory));
        factory.setGoogleValidator(validator);
        _updateGoogleKeys(GOOGLE_KEY);
        account = factory.createAccount(IDENTITY);
        device = vm.addr(DEVICE_PRIVATE_KEY);
    }

    function testDeterministicAddressAndIdempotentDeployment() public {
        address predicted = factory.getAddress(IDENTITY);
        _assertEq(address(account), predicted);
        _assertEq(address(factory.createAccount(IDENTITY)), predicted);
    }

    function testGoogleBootstrapAddsOnlyProofBoundDevice() public {
        PackedUserOperation memory op = _googleAddDeviceOp(device, ROOT_AUDIENCE, uint48(block.timestamp + 600));
        uint256 validationData = entryPoint.validate(account, op, keccak256("bootstrap"));
        _assertTrue(validationData != 1);

        bytes memory addDevice = abi.encodeCall(account.addDevice, (device));
        entryPoint.execute(account, address(account), 0, addDevice);
        _assertTrue(account.deviceKeys(device));
    }

    function testDeviceSignatureAcceptedAndUnknownDeviceRejected() public {
        _bootstrap(device);
        bytes32 userOpHash = keccak256("device-user-op");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_PRIVATE_KEY, userOpHash);
        PackedUserOperation memory op;
        op.sender = address(account);
        op.signature = abi.encodePacked(uint8(0), r, s, v);
        _assertEq(entryPoint.validate(account, op, userOpHash), 0);

        (v, r, s) = vm.sign(0xB0B, userOpHash);
        op.signature = abi.encodePacked(uint8(0), r, s, v);
        _assertEq(entryPoint.validate(account, op, userOpHash), 1);
    }

    function testGoogleProofCannotBeReusedAfterDeviceInstallation() public {
        PackedUserOperation memory op = _googleAddDeviceOp(device, ROOT_AUDIENCE, uint48(block.timestamp + 600));
        _assertTrue(entryPoint.validate(account, op, keccak256("first-bootstrap")) != 1);
        entryPoint.execute(account, address(account), 0, abi.encodeCall(account.addDevice, (device)));
        _assertEq(entryPoint.validate(account, op, keccak256("replayed-bootstrap")), 1);
    }

    function testUnauthorizedAudienceRejected() public {
        PackedUserOperation memory op = _googleAddDeviceOp(device, keccak256("evil-audience"), uint48(block.timestamp + 600));
        vm.expectRevert(GoogleJWTValidator.AudienceNotAllowed.selector);
        entryPoint.validate(account, op, keccak256("bootstrap"));
    }

    function testExpiredProofRejected() public {
        vm.warp(1_000);
        PackedUserOperation memory op = _googleAddDeviceOp(device, ROOT_AUDIENCE, 999);
        vm.expectRevert(GoogleJWTValidator.AuthorizationExpired.selector);
        entryPoint.validate(account, op, keccak256("bootstrap"));
    }

    function testUnrecognizedGoogleKeyRejected() public {
        _updateGoogleKeys(keccak256("replacement-rsa-key"));
        PackedUserOperation memory op = _googleAddDeviceOp(device, ROOT_AUDIENCE, uint48(block.timestamp + 600));
        vm.expectRevert(GoogleJWTValidator.InvalidGoogleKey.selector);
        entryPoint.validate(account, op, keccak256("bootstrap"));
    }

    function testCREKeyRotationRevokesOldKeys() public {
        bytes32 replacement = keccak256("replacement-rsa-key");
        _updateGoogleKeys(replacement);
        _assertTrue(!registry.validKeys(GOOGLE_KEY));
        _assertTrue(registry.validKeys(replacement));
    }

    function testDirectKeyReportRejected() public {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = GOOGLE_KEY;
        bytes10 workflowName = registry.WORKFLOW_NAME();
        vm.expectRevert(
            abi.encodeWithSelector(GoogleKeyRegistry.InvalidForwarder.selector, address(this))
        );
        registry.onReport(
            abi.encodePacked(bytes32(0), workflowName, address(this)), abi.encode(keys)
        );
    }

    function testOnlyEntryPointCanValidateOrExecute() public {
        PackedUserOperation memory op;
        vm.expectRevert(GoogleAccount.OnlyEntryPoint.selector);
        account.validateUserOp(op, bytes32(0), 0);
        vm.expectRevert(GoogleAccount.OnlyEntryPoint.selector);
        account.execute(address(this), 0, "");
    }

    function testAdministrativeCallsRequireSelfCall() public {
        vm.expectRevert(GoogleAccount.OnlySelf.selector);
        account.addDevice(device);
        vm.expectRevert(GoogleAccount.OnlySelf.selector);
        account.addAudience(keccak256("another-audience"));
    }

    function _bootstrap(address authorizedDevice) private {
        PackedUserOperation memory op = _googleAddDeviceOp(
            authorizedDevice, ROOT_AUDIENCE, uint48(block.timestamp + 600)
        );
        entryPoint.validate(account, op, keccak256("bootstrap"));
        entryPoint.execute(account, address(account), 0, abi.encodeCall(account.addDevice, (authorizedDevice)));
    }

    function _updateGoogleKeys(bytes32 keyHash) private {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = keyHash;
        creForwarder.updateKeys(
            registry, keccak256("google-jwks-workflow"), registry.WORKFLOW_NAME(), address(this), keys
        );
    }

    function _googleAddDeviceOp(
        address authorizedDevice,
        bytes32 audience,
        uint48 validUntil
    ) private view returns (PackedUserOperation memory op) {
        bytes32[] memory inputs = new bytes32[](8);
        inputs[0] = IDENTITY;
        inputs[1] = audience;
        inputs[2] = bytes32(uint256(uint160(authorizedDevice)));
        inputs[3] = bytes32(block.chainid);
        inputs[4] = bytes32(uint256(uint160(address(factory))));
        inputs[5] = bytes32(uint256(validUntil));
        inputs[6] = GOOGLE_KEY;
        inputs[7] = bytes32(uint256(1));

        bytes memory inner = abi.encodeCall(account.addDevice, (authorizedDevice));
        op.sender = address(account);
        op.callData = abi.encodeCall(account.execute, (address(account), 0, inner));
        op.signature = abi.encodePacked(uint8(1), abi.encode(bytes("mock-proof"), inputs));
    }

    function _assertTrue(bool condition) private pure {
        require(condition, "assert true failed");
    }

    function _assertEq(address left, address right) private pure {
        require(left == right, "address mismatch");
    }

    function _assertEq(uint256 left, uint256 right) private pure {
        require(left == right, "uint mismatch");
    }
}
