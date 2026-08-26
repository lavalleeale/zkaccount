// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {GeneratedGoogleVerifier} from "../src/GeneratedGoogleVerifier.sol";
import {GoogleAccountFactory} from "../src/GoogleAccountFactory.sol";
import {GoogleJWTValidator} from "../src/GoogleJWTValidator.sol";
import {GoogleKeyRegistry} from "../src/GoogleKeyRegistry.sol";
import {IGoogleProofVerifier} from "../src/IGoogleProofVerifier.sol";
import {IEntryPoint} from "../src/interfaces/IEntryPoint.sol";

interface VmDeployAll {
    function envAddress(string calldata name) external returns (address);
    function envString(string calldata name) external returns (string memory);
    function createSelectFork(string calldata urlOrAlias) external returns (uint256);
    function startBroadcast() external;
    function stopBroadcast() external;
}

/// @notice Redeploys the complete protocol stack to Base Sepolia and Ethereum
/// Sepolia in one run, one chain at a time via `vm.createSelectFork`. `forge
/// script` simulates by default; pass `--broadcast --multi` for a live,
/// funded deployment to both networks.
contract DeployAll {
    VmDeployAll private constant vm = VmDeployAll(address(uint160(uint256(keccak256("hevm cheat code")))));

    event DeploymentComplete(
        uint256 indexed chainId,
        address indexed deployer,
        address verifier,
        address keyRegistry,
        address factory,
        address validator,
        address entryPoint,
        bytes32 rootAudience
    );

    /// @dev Same immutable factory inputs on every chain: the root Google
    /// client and its resulting audience must match across deployments so
    /// both apps derive the same account address for a given identity.
    function run() external {
        address entryPoint = vm.envAddress("ENTRY_POINT");
        address creWorkflowOwner = vm.envAddress("CRE_WORKFLOW_OWNER");
        string memory rootClientId = vm.envString("ROOT_GOOGLE_CLIENT_ID");

        _deployToChain(
            vm.envString("BASE_SEPOLIA_RPC_URL"),
            84532,
            entryPoint,
            vm.envAddress("BASE_SEPOLIA_CRE_FORWARDER"),
            creWorkflowOwner,
            rootClientId
        );

        _deployToChain(
            vm.envString("ETHEREUM_SEPOLIA_RPC_URL"),
            11155111,
            entryPoint,
            vm.envAddress("ETHEREUM_SEPOLIA_CRE_FORWARDER"),
            creWorkflowOwner,
            rootClientId
        );
    }

    function _deployToChain(
        string memory rpcUrl,
        uint256 expectedChainId,
        address entryPoint,
        address creForwarder,
        address creWorkflowOwner,
        string memory rootClientId
    ) internal {
        vm.createSelectFork(rpcUrl);
        require(block.chainid == expectedChainId, "DeployAll: unexpected chain id for RPC");
        require(entryPoint.code.length != 0, "DeployAll: EntryPoint has no code");
        require(bytes(rootClientId).length != 0, "DeployAll: empty Google client ID");
        _requireP256Precompile();

        address deployer = msg.sender;
        vm.startBroadcast();
        GeneratedGoogleVerifier verifier = new GeneratedGoogleVerifier();
        GoogleKeyRegistry keyRegistry = new GoogleKeyRegistry(deployer, creForwarder, creWorkflowOwner);
        GoogleAccountFactory factory = new GoogleAccountFactory(IEntryPoint(entryPoint), rootClientId);
        GoogleJWTValidator validator =
            new GoogleJWTValidator(IGoogleProofVerifier(address(verifier)), keyRegistry, address(factory));
        factory.setGoogleValidator(validator);
        vm.stopBroadcast();

        require(address(factory.googleValidator()) == address(validator), "DeployAll: validator binding failed");
        require(address(validator.factory()) == address(factory), "DeployAll: validator factory mismatch");
        require(address(validator.verifier()) == address(verifier), "DeployAll: verifier mismatch");
        require(address(validator.keyRegistry()) == address(keyRegistry), "DeployAll: registry mismatch");

        emit DeploymentComplete(
            block.chainid,
            deployer,
            address(verifier),
            address(keyRegistry),
            address(factory),
            address(validator),
            entryPoint,
            factory.rootAudience()
        );
    }

    function _requireP256Precompile() private view {
        bytes memory input = abi.encodePacked(
            bytes32(0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023),
            bytes32(uint256(5)),
            bytes32(uint256(1)),
            bytes32(0xa71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957),
            bytes32(0x5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b)
        );
        (bool ok, bytes memory output) = address(0x100).staticcall(input);
        require(ok && output.length == 32 && abi.decode(output, (uint256)) == 1, "DeployAll: P-256 precompile unavailable");
    }
}
