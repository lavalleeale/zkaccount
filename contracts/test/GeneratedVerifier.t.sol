// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {GeneratedGoogleVerifier} from "../src/GeneratedGoogleVerifier.sol";

interface VmVerifier {
    function readFileBinary(string calldata path) external view returns (bytes memory);
}

contract GeneratedVerifierTest {
    VmVerifier private constant vm = VmVerifier(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testGeneratedVerifierAcceptsRealCircuitProof() public {
        GeneratedGoogleVerifier verifier = new GeneratedGoogleVerifier();
        bytes memory proof = vm.readFileBinary("contracts/test/fixtures/google-proof.bin");
        bytes memory encodedInputs = vm.readFileBinary("contracts/test/fixtures/google-public-inputs.bin");
        bytes32[] memory publicInputs = _decodePublicInputs(encodedInputs);
        require(verifier.verify(proof, publicInputs), "generated verifier rejected real proof");
    }

    function testGeneratedVerifierRejectsChangedIdentity() public {
        GeneratedGoogleVerifier verifier = new GeneratedGoogleVerifier();
        bytes memory proof = vm.readFileBinary("contracts/test/fixtures/google-proof.bin");
        bytes memory encodedInputs = vm.readFileBinary("contracts/test/fixtures/google-public-inputs.bin");
        bytes32[] memory publicInputs = _decodePublicInputs(encodedInputs);
        publicInputs[0] = bytes32(uint256(publicInputs[0]) + 1);
        (bool ok, bytes memory result) = address(verifier).staticcall(
            abi.encodeCall(verifier.verify, (proof, publicInputs))
        );
        require(!ok || !abi.decode(result, (bool)), "generated verifier accepted changed identity");
    }

    function _decodePublicInputs(bytes memory encoded) private pure returns (bytes32[] memory values) {
        require(encoded.length == 7 * 32, "unexpected public input length");
        values = new bytes32[](7);
        for (uint256 i = 0; i < 7; ++i) {
            bytes32 value;
            assembly ("memory-safe") {
                value := mload(add(add(encoded, 0x20), mul(i, 0x20)))
            }
            values[i] = value;
        }
    }
}
