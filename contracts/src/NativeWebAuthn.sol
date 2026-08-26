// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";

/// @notice WebAuthn assertion verification that deliberately requires the
/// EIP-7951/RIP-7212 P-256 precompile instead of a Solidity fallback.
library NativeWebAuthn {
    bytes1 private constant AUTH_DATA_FLAGS_UP = 0x01;
    bytes1 private constant AUTH_DATA_FLAGS_UV = 0x04;
    bytes1 private constant AUTH_DATA_FLAGS_BE = 0x08;
    bytes1 private constant AUTH_DATA_FLAGS_BS = 0x10;

    function verify(
        bytes32 challenge,
        bytes32 expectedRpIdHash,
        WebAuthn.WebAuthnAuth calldata auth,
        bytes32 qx,
        bytes32 qy
    ) internal view returns (bool) {
        bytes calldata authenticatorData = auth.authenticatorData;
        if (authenticatorData.length < 37) return false;
        if (bytes32(authenticatorData[:32]) != expectedRpIdHash) return false;

        bytes1 flags = authenticatorData[32];
        if ((flags & AUTH_DATA_FLAGS_UP) == 0 || (flags & AUTH_DATA_FLAGS_UV) == 0) return false;
        if ((flags & AUTH_DATA_FLAGS_BS) != 0 && (flags & AUTH_DATA_FLAGS_BE) == 0) return false;

        bytes memory clientDataJSON = bytes(auth.clientDataJSON);
        if (!_matches(clientDataJSON, auth.typeIndex, bytes('"type":"webauthn.get"'))) return false;
        bytes memory expectedChallenge =
            bytes(string.concat('"challenge":"', Base64.encodeURL(abi.encodePacked(challenge)), '"'));
        if (!_matches(clientDataJSON, auth.challengeIndex, expectedChallenge)) return false;

        bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, sha256(clientDataJSON)));
        return P256.verifyNative(messageHash, auth.r, auth.s, qx, qy);
    }

    function _matches(bytes memory value, uint256 offset, bytes memory expected) private pure returns (bool) {
        if (offset > value.length || expected.length > value.length - offset) return false;
        for (uint256 i = 0; i < expected.length; ++i) {
            if (value[offset + i] != expected[i]) return false;
        }
        return true;
    }
}
