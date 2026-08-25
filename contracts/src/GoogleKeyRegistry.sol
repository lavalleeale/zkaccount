// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ICREReceiver {
    function onReport(bytes calldata metadata, bytes calldata report) external;
}

contract GoogleKeyRegistry is ICREReceiver {
    error NotOwner();
    error ZeroAddress();
    error InvalidForwarder(address sender);
    error InvalidMetadata();
    error InvalidWorkflowOwner(address received, address expected);
    error InvalidWorkflowName(bytes10 received, bytes10 expected);
    error InvalidKeyCount(uint256 count);
    error DuplicateKey(bytes32 keyHash);

    uint256 public constant MAX_KEYS = 16;
    // CRE encodes the first 10 hex characters of SHA-256(workflow name)
    // as ASCII in forwarder metadata. SHA-256("googlejwks") starts 7cf25cd052.
    bytes10 public constant WORKFLOW_NAME = "7cf25cd052";

    address public owner;
    address public immutable forwarder;
    address public immutable workflowOwner;
    uint256 public lastUpdatedAt;
    bytes32 public latestKeySetHash;

    mapping(bytes32 keyHash => bool valid) public validKeys;
    bytes32[] private s_keys;

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    event KeyValiditySet(bytes32 indexed keyHash, bool valid);
    event KeySetUpdated(bytes32 indexed keySetHash, uint256 keyCount, uint256 updatedAt);

    constructor(address initialOwner, address creForwarder, address creWorkflowOwner) {
        if (initialOwner == address(0) || creForwarder == address(0) || creWorkflowOwner == address(0)) {
            revert ZeroAddress();
        }
        owner = initialOwner;
        forwarder = creForwarder;
        workflowOwner = creWorkflowOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @notice Replaces the complete Google key set with the set reported by CRE.
    /// @dev `report` is the ABI encoding of a sorted `bytes32[]`.
    function onReport(bytes calldata metadata, bytes calldata report) external {
        if (msg.sender != forwarder) revert InvalidForwarder(msg.sender);
        (bytes10 workflowName, address reportWorkflowOwner) = _decodeMetadata(metadata);
        if (reportWorkflowOwner != workflowOwner) {
            revert InvalidWorkflowOwner(reportWorkflowOwner, workflowOwner);
        }
        if (workflowName != WORKFLOW_NAME) {
            revert InvalidWorkflowName(workflowName, WORKFLOW_NAME);
        }

        bytes32[] memory newKeys = abi.decode(report, (bytes32[]));
        uint256 newKeyCount = newKeys.length;
        if (newKeyCount == 0 || newKeyCount > MAX_KEYS) revert InvalidKeyCount(newKeyCount);

        for (uint256 i; i < newKeyCount; ++i) {
            bytes32 keyHash = newKeys[i];
            for (uint256 j; j < i; ++j) {
                if (newKeys[j] == keyHash) revert DuplicateKey(keyHash);
            }
        }

        uint256 oldKeyCount = s_keys.length;
        for (uint256 i; i < oldKeyCount; ++i) {
            bytes32 keyHash = s_keys[i];
            validKeys[keyHash] = false;
            emit KeyValiditySet(keyHash, false);
        }
        delete s_keys;

        for (uint256 i; i < newKeyCount; ++i) {
            bytes32 keyHash = newKeys[i];
            validKeys[keyHash] = true;
            s_keys.push(keyHash);
            emit KeyValiditySet(keyHash, true);
        }

        bytes32 keySetHash = keccak256(abi.encode(newKeys));
        latestKeySetHash = keySetHash;
        lastUpdatedAt = block.timestamp;
        emit KeySetUpdated(keySetHash, newKeyCount, block.timestamp);
    }

    function keys() external view returns (bytes32[] memory) {
        return s_keys;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(ICREReceiver).interfaceId || interfaceId == 0x01ffc9a7;
    }

    /// @dev CRE metadata is workflowId (32 bytes), workflowName (10 bytes),
    /// then workflowOwner (20 bytes), packed by the Keystone forwarder.
    function _decodeMetadata(bytes calldata metadata)
        private
        pure
        returns (bytes10 workflowName, address reportWorkflowOwner)
    {
        if (metadata.length < 62) revert InvalidMetadata();
        assembly {
            workflowName := calldataload(add(metadata.offset, 32))
            reportWorkflowOwner := shr(96, calldataload(add(metadata.offset, 42)))
        }
    }
}
