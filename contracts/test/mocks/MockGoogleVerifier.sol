// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IGoogleProofVerifier} from "../../src/IGoogleProofVerifier.sol";

contract MockGoogleVerifier is IGoogleProofVerifier {
    bool public result = true;

    function setResult(bool result_) external {
        result = result_;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return result;
    }
}

