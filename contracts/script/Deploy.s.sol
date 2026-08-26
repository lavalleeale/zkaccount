// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {GeneratedGoogleVerifier} from "../src/GeneratedGoogleVerifier.sol";
import {GoogleAccountFactory} from "../src/GoogleAccountFactory.sol";
import {GoogleJWTValidator} from "../src/GoogleJWTValidator.sol";
import {GoogleKeyRegistry} from "../src/GoogleKeyRegistry.sol";
import {IGoogleProofVerifier} from "../src/IGoogleProofVerifier.sol";
import {IEntryPoint} from "../src/interfaces/IEntryPoint.sol";

interface VmDeploy {
    function envAddress(string calldata name) external returns (address);
    function envString(string calldata name) external returns (string memory);
    function startBroadcast() external;
    function stopBroadcast() external;
}

/// @notice Deploys the complete current protocol stack. `forge script` simulates
/// by default; pass `--broadcast` explicitly when a funded deployment is intended.
contract Deploy {
    VmDeploy private constant vm = VmDeploy(address(uint160(uint256(keccak256("hevm cheat code")))));

    event DeploymentComplete(
        address indexed deployer,
        address verifier,
        address keyRegistry,
        address factory,
        address validator,
        address entryPoint,
        bytes32 rootAudience
    );

    function run()
        external
        returns (
            GeneratedGoogleVerifier verifier,
            GoogleKeyRegistry keyRegistry,
            GoogleAccountFactory factory,
            GoogleJWTValidator validator
        )
    {
        address deployer = msg.sender;
        address entryPoint = vm.envAddress("ENTRY_POINT");
        address creForwarder = vm.envAddress("CRE_FORWARDER");
        address creWorkflowOwner = vm.envAddress("CRE_WORKFLOW_OWNER");
        string memory rootClientId = vm.envString("ROOT_GOOGLE_CLIENT_ID");

        require(
            block.chainid == 84532 || block.chainid == 11155111,
            "Deploy: supported Sepolia testnets only"
        );
        require(entryPoint.code.length != 0, "Deploy: EntryPoint has no code");
        require(bytes(rootClientId).length != 0, "Deploy: empty Google client ID");

        vm.startBroadcast();
        verifier = new GeneratedGoogleVerifier();
        keyRegistry = new GoogleKeyRegistry(deployer, creForwarder, creWorkflowOwner);
        factory = new GoogleAccountFactory(IEntryPoint(entryPoint), rootClientId);
        validator = new GoogleJWTValidator(
            IGoogleProofVerifier(address(verifier)), keyRegistry, address(factory)
        );
        factory.setGoogleValidator(validator);
        vm.stopBroadcast();

        require(address(factory.googleValidator()) == address(validator), "Deploy: validator binding failed");
        require(address(validator.factory()) == address(factory), "Deploy: validator factory mismatch");
        require(address(validator.verifier()) == address(verifier), "Deploy: verifier mismatch");
        require(address(validator.keyRegistry()) == address(keyRegistry), "Deploy: registry mismatch");

        emit DeploymentComplete(
            deployer,
            address(verifier),
            address(keyRegistry),
            address(factory),
            address(validator),
            entryPoint,
            factory.rootAudience()
        );
    }
}
