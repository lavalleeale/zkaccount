// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {GoogleAccount} from "../src/GoogleAccount.sol";
import {GoogleAccountFactory} from "../src/GoogleAccountFactory.sol";
import {GoogleJWTValidator} from "../src/GoogleJWTValidator.sol";
import {GoogleKeyRegistry} from "../src/GoogleKeyRegistry.sol";
import {IEntryPoint, PackedUserOperation} from "../src/interfaces/IEntryPoint.sol";
import {MockGoogleVerifier} from "./mocks/MockGoogleVerifier.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";

interface Vm {
    function etch(address target, bytes calldata code) external;
    function prank(address sender) external;
    function expectRevert(bytes4 selector) external;
    function expectRevert(bytes calldata revertData) external;
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData, address emitter) external;
    function warp(uint256 timestamp) external;
}

contract MockP256Precompile {
    bytes32 private constant R = bytes32(uint256(5));
    bytes32 private constant S = bytes32(uint256(1));
    bytes32 private constant QX = 0xa71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957;
    bytes32 private constant QY = 0x5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b;

    fallback(bytes calldata input) external returns (bytes memory) {
        bool valid;
        if (input.length == 160) {
            bytes32 r;
            bytes32 s;
            bytes32 qx;
            bytes32 qy;
            assembly ("memory-safe") {
                r := calldataload(add(input.offset, 32))
                s := calldataload(add(input.offset, 64))
                qx := calldataload(add(input.offset, 96))
                qy := calldataload(add(input.offset, 128))
            }
            valid = r == R && s == S && qx == QX && qy == QY;
        }
        assembly ("memory-safe") {
            if valid {
                mstore(0, 1)
                return(0, 32)
            }
            return(0, 0)
        }
    }
}

contract MockCREForwarder {
    function updateKeys(
        GoogleKeyRegistry registry,
        bytes32 workflowId,
        bytes10 workflowName,
        address workflowOwner,
        bytes32[] memory keys
    ) external {
        registry.onReport(abi.encodePacked(workflowId, workflowName, workflowOwner), abi.encode(keys));
    }
}

contract MockEntryPoint is IEntryPoint {
    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32) {
        return
            keccak256(abi.encode(userOp.sender, userOp.nonce, keccak256(userOp.callData), block.chainid, address(this)));
    }

    function validate(GoogleAccount account, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        returns (uint256)
    {
        return account.validateUserOp(userOp, userOpHash, 0);
    }

    function execute(GoogleAccount account, address target, uint256 value, bytes calldata data) external {
        account.execute(target, value, data);
    }
}

contract GoogleAccountTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    bytes32 private constant P256_R = bytes32(uint256(5));
    bytes32 private constant P256_S = bytes32(uint256(1));
    bytes32 private constant P256_QX = 0xa71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957;
    bytes32 private constant P256_QY = 0x5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b;
    string private constant RP_ID = "localhost-rp-id";
    bytes32 private constant IDENTITY = keccak256("google-sub-fixture");
    string private constant ROOT_CLIENT_ID = "root.apps.googleusercontent.com";
    bytes32 private constant GOOGLE_KEY = keccak256("fixture-rsa-key");
    uint8 private constant ACTION_ADD_DEVICE = 1;
    uint8 private constant ACTION_REMOVE_DEVICE = 2;

    event DeviceSet(address indexed device, bool enabled, string rpId);

    MockEntryPoint private entryPoint;
    MockGoogleVerifier private verifier;
    MockCREForwarder private creForwarder;
    GoogleKeyRegistry private registry;
    GoogleAccountFactory private factory;
    GoogleJWTValidator private validator;
    GoogleAccount private account;
    address private device;
    bytes32 private rpIdHash;
    bytes32 private rootAudience;

    function setUp() public {
        entryPoint = new MockEntryPoint();
        verifier = new MockGoogleVerifier();
        creForwarder = new MockCREForwarder();
        registry = new GoogleKeyRegistry(address(this), address(creForwarder), address(this));
        factory = new GoogleAccountFactory(entryPoint, ROOT_CLIENT_ID);
        rootAudience = bytes32(uint256(sha256(bytes(ROOT_CLIENT_ID))) & type(uint248).max);
        validator = new GoogleJWTValidator(verifier, registry, address(factory));
        factory.setGoogleValidator(validator);
        _updateGoogleKeys(GOOGLE_KEY);
        account = factory.createAccount(IDENTITY);
        rpIdHash = sha256(bytes(RP_ID));
        device = account.deviceIdentifier(P256_QX, P256_QY, rpIdHash);
        MockP256Precompile p256 = new MockP256Precompile();
        vm.etch(address(0x100), address(p256).code);
    }

    function testDeterministicAddressAndIdempotentDeployment() public {
        address predicted = factory.getAddress(IDENTITY);
        _assertEq(address(account), predicted);
        _assertEq(address(factory.createAccount(IDENTITY)), predicted);
    }

    function testGoogleBootstrapAddsOnlyProofBoundDevice() public {
        PackedUserOperation memory op = _googleAddDeviceOp(P256_QX, rootAudience, uint48(block.timestamp + 600));
        uint256 validationData = entryPoint.validate(account, op, keccak256("bootstrap"));
        _assertTrue(validationData != 1);

        bytes memory queueDevice = _queueDeviceCall(P256_QX);
        entryPoint.execute(account, address(account), 0, queueDevice);
        _assertTrue(account.deviceKeys(device));
    }

    function testGoogleBootstrapEmitsCleartextRpId() public {
        PackedUserOperation memory op = _googleAddDeviceOp(P256_QX, rootAudience, uint48(block.timestamp + 600));
        entryPoint.validate(account, op, keccak256("bootstrap"));

        vm.expectEmit(true, false, false, true, address(account));
        emit DeviceSet(device, true, RP_ID);
        entryPoint.execute(account, address(account), 0, _queueDeviceCall(P256_QX));
    }

    function testGoogleBootstrapRejectsSubstitutedWebAuthnKey() public {
        PackedUserOperation memory op = _googleAddDeviceOp(P256_QX, rootAudience, uint48(block.timestamp + 600));
        op.callData =
            abi.encodeCall(account.execute, (address(account), 0, _queueDeviceCall(bytes32(uint256(P256_QX) + 1))));
        vm.expectRevert(GoogleAccount.InvalidGoogleCallData.selector);
        entryPoint.validate(account, op, keccak256("substituted-key"));
    }

    function testGoogleBootstrapRejectsMismatchedRpId() public {
        PackedUserOperation memory op = _googleAddDeviceOp(P256_QX, rootAudience, uint48(block.timestamp + 600));
        bytes memory wrongRpIdCall = abi.encodeCall(
            account.execute,
            (address(account), 0, abi.encodeCall(account.queueDevice, (device, P256_QX, P256_QY, "wrong-rp-id")))
        );
        op.callData = wrongRpIdCall;
        vm.expectRevert(GoogleAccount.InvalidGoogleCallData.selector);
        entryPoint.validate(account, op, keccak256("wrong-rp-id"));
    }

    function testDeviceSignatureAcceptedAndUnknownDeviceRejected() public {
        _bootstrap();
        bytes32 userOpHash = keccak256("device-user-op");
        PackedUserOperation memory op;
        op.sender = address(account);
        op.signature = _webAuthnSignature(device, userOpHash, rpIdHash, P256_R);
        _assertEq(entryPoint.validate(account, op, userOpHash), 0);

        op.signature = _webAuthnSignature(address(0xB0B), userOpHash, rpIdHash, P256_R);
        _assertEq(entryPoint.validate(account, op, userOpHash), 1);
    }

    function testERC1271AcceptsAuthorizedDeviceSignature() public {
        _bootstrap();
        bytes32 digest = keccak256("signed-message");
        bytes memory signature = _webAuthnSignature(device, digest, rpIdHash, P256_R);

        _assertEq(account.isValidSignature(digest, signature), account.ERC1271_MAGIC_VALUE());
        _assertEq(
            account.isValidSignature(keccak256("different-message"), signature), account.ERC1271_INVALID_SIGNATURE()
        );
    }

    function testERC1271RejectsUnknownAndRevokedDevices() public {
        _bootstrap();
        bytes32 digest = keccak256("signed-message");
        _assertEq(
            account.isValidSignature(digest, _webAuthnSignature(address(0xB0B), digest, rpIdHash, P256_R)),
            account.ERC1271_INVALID_SIGNATURE()
        );

        entryPoint.execute(account, address(account), 0, abi.encodeCall(account.removeDevice, (device)));
        _assertEq(
            account.isValidSignature(digest, _webAuthnSignature(device, digest, rpIdHash, P256_R)),
            account.ERC1271_INVALID_SIGNATURE()
        );
    }

    function testERC1271RejectsMalformedWrongRpIdAndInvalidP256Signatures() public {
        _bootstrap();
        bytes32 digest = keccak256("signed-message");

        _assertEq(account.isValidSignature(digest, hex"1234"), account.ERC1271_INVALID_SIGNATURE());
        _assertEq(
            account.isValidSignature(digest, _webAuthnSignature(device, digest, keccak256("wrong-rp"), P256_R)),
            account.ERC1271_INVALID_SIGNATURE()
        );
        _assertEq(
            account.isValidSignature(digest, _webAuthnSignature(device, digest, rpIdHash, bytes32(uint256(6)))),
            account.ERC1271_INVALID_SIGNATURE()
        );
    }

    function testERC1271RejectsWrongTypeAndMissingUserVerification() public {
        _bootstrap();
        bytes32 digest = keccak256("signed-message");
        _assertEq(
            account.isValidSignature(
                digest, _webAuthnSignatureWith(device, digest, rpIdHash, P256_R, 0x05, "webauthn.create")
            ),
            account.ERC1271_INVALID_SIGNATURE()
        );
        _assertEq(
            account.isValidSignature(
                digest, _webAuthnSignatureWith(device, digest, rpIdHash, P256_R, 0x01, "webauthn.get")
            ),
            account.ERC1271_INVALID_SIGNATURE()
        );
    }

    function testGoogleProofCannotBeReusedAfterDeviceInstallation() public {
        PackedUserOperation memory op = _googleAddDeviceOp(P256_QX, rootAudience, uint48(block.timestamp + 600));
        _assertTrue(entryPoint.validate(account, op, keccak256("first-bootstrap")) != 1);
        entryPoint.execute(account, address(account), 0, _queueDeviceCall(P256_QX));
        _assertEq(entryPoint.validate(account, op, keccak256("replayed-bootstrap")), 1);
    }

    function testGoogleNonceMustStrictlyIncrease() public {
        PackedUserOperation memory first = _googleAddDeviceOp(P256_QX, rootAudience, uint48(block.timestamp + 600), 100);
        _assertTrue(entryPoint.validate(account, first, keccak256("first")) != 1);
        _assertEq(account.googleNonce(), 100);

        PackedUserOperation memory equal =
            _googleAddDeviceOp(bytes32(uint256(P256_QX) + 1), rootAudience, uint48(block.timestamp + 600), 100);
        vm.expectRevert(abi.encodeWithSelector(GoogleAccount.GoogleNonceNotIncreasing.selector, 100, 100));
        entryPoint.validate(account, equal, keccak256("equal"));

        PackedUserOperation memory lower =
            _googleAddDeviceOp(bytes32(uint256(P256_QX) + 2), rootAudience, uint48(block.timestamp + 600), 99);
        vm.expectRevert(abi.encodeWithSelector(GoogleAccount.GoogleNonceNotIncreasing.selector, 99, 100));
        entryPoint.validate(account, lower, keccak256("lower"));

        PackedUserOperation memory higher =
            _googleAddDeviceOp(bytes32(uint256(P256_QX) + 3), rootAudience, uint48(block.timestamp + 600), 101);
        _assertTrue(entryPoint.validate(account, higher, keccak256("higher")) != 1);
        _assertEq(account.googleNonce(), 101);
    }

    function testGoogleProofCannotBeReusedAfterDeviceRemoval() public {
        PackedUserOperation memory op = _googleAddDeviceOp(P256_QX, rootAudience, uint48(block.timestamp + 600), 100);
        _assertTrue(entryPoint.validate(account, op, keccak256("bootstrap")) != 1);
        entryPoint.execute(account, address(account), 0, _queueDeviceCall(P256_QX));
        entryPoint.execute(account, address(account), 0, abi.encodeCall(account.removeDevice, (device)));
        _assertTrue(!account.deviceKeys(device));

        vm.expectRevert(abi.encodeWithSelector(GoogleAccount.GoogleNonceNotIncreasing.selector, 100, 100));
        entryPoint.validate(account, op, keccak256("replay-after-removal"));
    }

    function testSimultaneousGoogleLoginsWithSameIatOnlyConsumeOnce() public {
        PackedUserOperation memory first = _googleAddDeviceOp(P256_QX, rootAudience, uint48(block.timestamp + 600), 100);
        PackedUserOperation memory second =
            _googleAddDeviceOp(bytes32(uint256(P256_QX) + 1), rootAudience, uint48(block.timestamp + 600), 100);

        _assertTrue(entryPoint.validate(account, first, keccak256("first-login")) != 1);
        vm.expectRevert(abi.encodeWithSelector(GoogleAccount.GoogleNonceNotIncreasing.selector, 100, 100));
        entryPoint.validate(account, second, keccak256("simultaneous-login"));
    }

    /// @notice Device removal is only reachable through a device-signed UserOp
    /// (see `testERC1271RejectsUnknownAndRevokedDevices`); Google proofs may
    /// only authorize adding a device.
    function testGoogleAuthorizedRemovalIsRejected() public {
        _bootstrap();
        _assertTrue(account.deviceKeys(device));

        PackedUserOperation memory op = _googleRemoveDeviceOp(device, rootAudience, uint48(block.timestamp + 600), 1_000);
        vm.expectRevert(GoogleJWTValidator.InvalidAction.selector);
        entryPoint.validate(account, op, keccak256("revoke"));
        _assertTrue(account.deviceKeys(device));
    }

    function testWrongAudienceRejected() public {
        PackedUserOperation memory op =
            _googleAddDeviceOp(P256_QX, keccak256("evil-audience"), uint48(block.timestamp + 600));
        vm.expectRevert(GoogleJWTValidator.WrongAudience.selector);
        entryPoint.validate(account, op, keccak256("bootstrap"));
    }

    function testExpiredProofRejected() public {
        vm.warp(1_000);
        PackedUserOperation memory op = _googleAddDeviceOp(P256_QX, rootAudience, 999);
        vm.expectRevert(GoogleJWTValidator.AuthorizationExpired.selector);
        entryPoint.validate(account, op, keccak256("bootstrap"));
    }

    function testUnrecognizedGoogleKeyRejected() public {
        _updateGoogleKeys(keccak256("replacement-rsa-key"));
        PackedUserOperation memory op = _googleAddDeviceOp(P256_QX, rootAudience, uint48(block.timestamp + 600));
        vm.expectRevert(GoogleJWTValidator.InvalidGoogleKey.selector);
        entryPoint.validate(account, op, keccak256("bootstrap"));
    }

    function testUnsupportedActionRejected() public {
        PackedUserOperation memory op = _googleOp(P256_QX, rootAudience, uint48(block.timestamp + 600), 100, 3);
        vm.expectRevert(GoogleJWTValidator.InvalidAction.selector);
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
        vm.expectRevert(abi.encodeWithSelector(GoogleKeyRegistry.InvalidForwarder.selector, address(this)));
        registry.onReport(abi.encodePacked(bytes32(0), workflowName, address(this)), abi.encode(keys));
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
        account.addDevice(device, P256_QX, P256_QY, RP_ID);
        vm.expectRevert(GoogleAccount.OnlySelf.selector);
        account.removeDevice(device);
        vm.expectRevert(GoogleAccount.OnlySelf.selector);
        account.removeAllDevices(new address[](0));
        vm.expectRevert(GoogleAccount.OnlySelf.selector);
        account.queueDevice(device, P256_QX, P256_QY, RP_ID);
        vm.expectRevert(GoogleAccount.OnlySelf.selector);
        account.approveDevice(device);
        vm.expectRevert(GoogleAccount.OnlySelf.selector);
        account.cancelPendingDevice(device);
    }

    function testGoogleAddedSecondDeviceIsTimelockedNotInstant() public {
        _bootstrap();
        address secondDevice = _queueSecondDeviceViaGoogle();

        _assertTrue(!account.deviceKeys(secondDevice));
        vm.expectRevert(GoogleAccount.TimelockNotElapsed.selector);
        account.finalizeDevice(secondDevice);
    }

    function testFinalizeDeviceActivatesAfterDelayAndIsPermissionless() public {
        _bootstrap();
        address secondDevice = _queueSecondDeviceViaGoogle();

        vm.warp(block.timestamp + account.DEVICE_ADD_DELAY());
        // No prank/self-call needed: finalizing an already-timelocked device is
        // permissionless since the delay itself is the authorization.
        account.finalizeDevice(secondDevice);
        _assertTrue(account.deviceKeys(secondDevice));
    }

    function testFinalizeDeviceWithoutPendingEntryReverts() public {
        _bootstrap();
        vm.expectRevert(GoogleAccount.NoPendingDevice.selector);
        account.finalizeDevice(address(0xB0B));
    }

    function testExistingDeviceCanCancelPendingDevice() public {
        _bootstrap();
        address secondDevice = _queueSecondDeviceViaGoogle();

        entryPoint.execute(account, address(account), 0, abi.encodeCall(account.cancelPendingDevice, (secondDevice)));

        vm.warp(block.timestamp + account.DEVICE_ADD_DELAY());
        vm.expectRevert(GoogleAccount.NoPendingDevice.selector);
        account.finalizeDevice(secondDevice);
        _assertTrue(!account.deviceKeys(secondDevice));
    }

    function testExistingDeviceCanApproveDeviceToSkipTheDelay() public {
        _bootstrap();
        address secondDevice = _queueSecondDeviceViaGoogle();

        entryPoint.execute(account, address(account), 0, abi.encodeCall(account.approveDevice, (secondDevice)));

        _assertTrue(account.deviceKeys(secondDevice));
    }

    function testApproveDeviceWithoutPendingEntryReverts() public {
        _bootstrap();
        // approveDevice is onlySelf, so it's only reachable through execute(),
        // which wraps the inner revert reason in CallFailed.
        vm.expectRevert(
            abi.encodeWithSelector(
                GoogleAccount.CallFailed.selector, abi.encodeWithSelector(GoogleAccount.NoPendingDevice.selector)
            )
        );
        entryPoint.execute(account, address(account), 0, abi.encodeCall(account.approveDevice, (address(0xB0B))));
    }

    function testRemoveAllDevicesClearsEveryProvidedDevice() public {
        _bootstrap();
        address secondDevice = account.deviceIdentifier(bytes32(uint256(P256_QX) + 1), P256_QY, rpIdHash);
        entryPoint.execute(
            account,
            address(account),
            0,
            abi.encodeCall(account.addDevice, (secondDevice, bytes32(uint256(P256_QX) + 1), P256_QY, RP_ID))
        );
        _assertTrue(account.deviceKeys(device));
        _assertTrue(account.deviceKeys(secondDevice));

        address[] memory devices = new address[](2);
        devices[0] = device;
        devices[1] = secondDevice;
        entryPoint.execute(account, address(account), 0, abi.encodeCall(account.removeAllDevices, (devices)));

        _assertTrue(!account.deviceKeys(device));
        _assertTrue(!account.deviceKeys(secondDevice));
    }

    function _bootstrap() private {
        PackedUserOperation memory op = _googleAddDeviceOp(P256_QX, rootAudience, uint48(block.timestamp + 600));
        entryPoint.validate(account, op, keccak256("bootstrap"));
        entryPoint.execute(account, address(account), 0, _queueDeviceCall(P256_QX));
    }

    /// @dev Queues a second device via a fresh Google proof once the account
    /// already has one enabled device, so it lands behind the timelock instead
    /// of activating immediately like the bootstrap device does.
    function _queueSecondDeviceViaGoogle() private returns (address secondDevice) {
        bytes32 secondQx = bytes32(uint256(P256_QX) + 1);
        secondDevice = account.deviceIdentifier(secondQx, P256_QY, rpIdHash);
        // Bootstrap already consumed a googleNonce derived from the same
        // block.timestamp (validUntil - 300); this must strictly exceed it.
        uint64 issuedAt = uint64(block.timestamp) + 500;
        PackedUserOperation memory op =
            _googleAddDeviceOp(secondQx, rootAudience, uint48(block.timestamp + 600), issuedAt);
        entryPoint.validate(account, op, keccak256("second-device"));
        entryPoint.execute(account, address(account), 0, _queueDeviceCall(secondQx));
    }

    function _updateGoogleKeys(bytes32 keyHash) private {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = keyHash;
        creForwarder.updateKeys(
            registry, keccak256("google-jwks-workflow"), registry.WORKFLOW_NAME(), address(this), keys
        );
    }

    function _googleAddDeviceOp(bytes32 qx, bytes32 audience, uint48 validUntil)
        private
        view
        returns (PackedUserOperation memory op)
    {
        return _googleAddDeviceOp(qx, audience, validUntil, uint64(validUntil - 300));
    }

    function _googleAddDeviceOp(bytes32 qx, bytes32 audience, uint48 validUntil, uint64 issuedAt)
        private
        view
        returns (PackedUserOperation memory op)
    {
        address authorizedDevice = account.deviceIdentifier(qx, P256_QY, rpIdHash);
        bytes32[] memory inputs =
            _publicInputs(bytes32(uint256(uint160(authorizedDevice))), audience, validUntil, issuedAt, ACTION_ADD_DEVICE);

        bytes memory inner = abi.encodeCall(account.queueDevice, (authorizedDevice, qx, P256_QY, RP_ID));
        op.sender = address(account);
        op.callData = abi.encodeCall(account.execute, (address(account), 0, inner));
        op.signature = abi.encodePacked(uint8(1), abi.encode(bytes("mock-proof"), inputs, qx, P256_QY, RP_ID));
    }

    function _googleRemoveDeviceOp(address targetDevice, bytes32 audience, uint48 validUntil, uint64 issuedAt)
        private
        view
        returns (PackedUserOperation memory op)
    {
        bytes32[] memory inputs = _publicInputs(
            bytes32(uint256(uint160(targetDevice))), audience, validUntil, issuedAt, ACTION_REMOVE_DEVICE
        );

        bytes memory inner = abi.encodeCall(account.removeDevice, (targetDevice));
        op.sender = address(account);
        op.callData = abi.encodeCall(account.execute, (address(account), 0, inner));
        op.signature = abi.encodePacked(uint8(1), abi.encode(bytes("mock-proof"), inputs, bytes32(0), bytes32(0), ""));
    }

    function _googleOp(bytes32 qx, bytes32 audience, uint48 validUntil, uint64 issuedAt, uint8 action)
        private
        view
        returns (PackedUserOperation memory op)
    {
        address authorizedDevice = account.deviceIdentifier(qx, P256_QY, rpIdHash);
        bytes32[] memory inputs =
            _publicInputs(bytes32(uint256(uint160(authorizedDevice))), audience, validUntil, issuedAt, action);

        bytes memory inner = abi.encodeCall(account.queueDevice, (authorizedDevice, qx, P256_QY, RP_ID));
        op.sender = address(account);
        op.callData = abi.encodeCall(account.execute, (address(account), 0, inner));
        op.signature = abi.encodePacked(uint8(1), abi.encode(bytes("mock-proof"), inputs, qx, P256_QY, RP_ID));
    }

    function _publicInputs(bytes32 deviceInput, bytes32 audience, uint48 validUntil, uint64 issuedAt, uint8 action)
        private
        view
        returns (bytes32[] memory inputs)
    {
        inputs = new bytes32[](9);
        inputs[0] = IDENTITY;
        inputs[1] = audience;
        inputs[2] = deviceInput;
        inputs[3] = bytes32(block.chainid);
        inputs[4] = bytes32(uint256(uint160(address(factory))));
        inputs[5] = bytes32(uint256(validUntil));
        inputs[6] = GOOGLE_KEY;
        inputs[7] = bytes32(uint256(issuedAt));
        inputs[8] = bytes32(uint256(action));
    }

    function _queueDeviceCall(bytes32 qx) private view returns (bytes memory) {
        address identifier = account.deviceIdentifier(qx, P256_QY, rpIdHash);
        return abi.encodeCall(account.queueDevice, (identifier, qx, P256_QY, RP_ID));
    }

    function _webAuthnSignature(address identifier, bytes32 challenge, bytes32 expectedRpIdHash, bytes32 r)
        private
        pure
        returns (bytes memory)
    {
        return _webAuthnSignatureWith(identifier, challenge, expectedRpIdHash, r, 0x05, "webauthn.get");
    }

    function _webAuthnSignatureWith(
        address identifier,
        bytes32 challenge,
        bytes32 expectedRpIdHash,
        bytes32 r,
        bytes1 flags,
        string memory assertionType
    ) private pure returns (bytes memory) {
        bytes memory authenticatorData = abi.encodePacked(expectedRpIdHash, flags, bytes4(0));
        string memory clientDataJSON = string.concat(
            '{"type":"',
            assertionType,
            '","challenge":"',
            Base64.encodeURL(abi.encodePacked(challenge)),
            '","origin":"https://example.test","crossOrigin":false}'
        );
        return abi.encodePacked(
            uint8(0),
            abi.encode(identifier),
            abi.encode(r, P256_S, uint256(23), uint256(1), authenticatorData, clientDataJSON)
        );
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

    function _assertEq(bytes4 left, bytes4 right) private pure {
        require(left == right, "bytes4 mismatch");
    }
}
