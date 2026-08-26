// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IGoogleProofVerifier} from "./IGoogleProofVerifier.sol";
import {GoogleKeyRegistry} from "./GoogleKeyRegistry.sol";

interface IGoogleAccountView {
    function identity() external view returns (bytes32);
}

interface IGoogleAccountFactoryView {
    function getAddress(bytes32 identity) external view returns (address);
    function rootAudience() external view returns (bytes32);
}

contract GoogleJWTValidator {
    uint256 public constant PUBLIC_INPUT_COUNT = 9;
    uint8 public constant ACTION_ADD_DEVICE = 1;

    error InvalidPublicInputCount();
    error InvalidProof();
    error InvalidGoogleKey();
    error AuthorizationExpired();
    error WrongChain();
    error WrongFactory();
    error WrongAccount();
    error WrongIdentity();
    error WrongAudience();
    error InvalidAction();
    error InvalidDevice();
    error InvalidGoogleNonce();

    struct GoogleAuthorization {
        bytes32 identity;
        bytes32 audience;
        address deviceKey;
        uint48 validUntil;
        uint64 googleNonce;
        uint8 action;
    }

    IGoogleProofVerifier public immutable verifier;
    GoogleKeyRegistry public immutable keyRegistry;
    address public immutable factory;

    // Public input order is part of the protocol and must match Noir exactly:
    // identity, audienceHash, device address, chainId, factory address,
    // validUntil, Google key hash and the JWT iat-backed Google nonce. This
    // verifier is dedicated to the add-device authorization circuit, so an
    // action discriminator is redundant.
    constructor(IGoogleProofVerifier verifier_, GoogleKeyRegistry keyRegistry_, address factory_) {
        verifier = verifier_;
        keyRegistry = keyRegistry_;
        factory = factory_;
    }

    function verifyGoogleAuthorization(
        address account,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external view returns (GoogleAuthorization memory auth) {
        if (publicInputs.length != PUBLIC_INPUT_COUNT) revert InvalidPublicInputCount();
        try verifier.verify(proof, publicInputs) returns (bool valid) {
            if (!valid) revert InvalidProof();
        } catch {
            // Generated UltraHonk verifiers revert for malformed/invalid proofs.
            // Normalize that backend-specific behavior into the policy API.
            revert InvalidProof();
        }

        auth.identity = publicInputs[0];
        auth.audience = publicInputs[1];
        auth.deviceKey = address(uint160(uint256(publicInputs[2])));
        uint256 validUntil = uint256(publicInputs[5]);
        auth.validUntil = uint48(validUntil);
        uint256 googleNonce = uint256(publicInputs[7]);
        auth.googleNonce = uint64(googleNonce);
        uint256 action = uint256(publicInputs[8]);

        if (uint256(publicInputs[2]) >> 160 != 0 || auth.deviceKey == address(0)) revert InvalidDevice();
        if (uint256(publicInputs[4]) >> 160 != 0 || address(uint160(uint256(publicInputs[4]))) != factory) {
            revert WrongFactory();
        }
        if (uint256(publicInputs[3]) != block.chainid) revert WrongChain();
        if (validUntil > type(uint48).max || block.timestamp > validUntil) revert AuthorizationExpired();
        if (googleNonce > type(uint64).max) revert InvalidGoogleNonce();
        if (action != ACTION_ADD_DEVICE) revert InvalidAction();
        auth.action = uint8(action);
        if (!keyRegistry.validKeys(publicInputs[6])) revert InvalidGoogleKey();
        if (IGoogleAccountView(account).identity() != auth.identity) revert WrongIdentity();
        if (IGoogleAccountFactoryView(factory).getAddress(auth.identity) != account) revert WrongAccount();
        if (auth.audience != IGoogleAccountFactoryView(factory).rootAudience()) revert WrongAudience();
    }
}
