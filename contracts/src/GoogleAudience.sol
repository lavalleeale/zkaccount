// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library GoogleAudience {
    function hash(string memory clientId) internal pure returns (bytes32) {
        return bytes32(uint256(sha256(bytes(clientId))) & type(uint248).max);
    }
}
