// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IEntryPoint} from "./interfaces/IEntryPoint.sol";
import {GoogleJWTValidator} from "./GoogleJWTValidator.sol";
import {GoogleAccount} from "./GoogleAccount.sol";

contract GoogleAccountFactory {
    error NotOwner();
    error ValidatorAlreadySet();
    error ValidatorNotSet();

    IEntryPoint public immutable entryPoint;
    bytes32 public immutable rootAudience;
    address public immutable owner;
    GoogleJWTValidator public googleValidator;

    event ValidatorSet(address indexed validator);
    event AccountCreated(bytes32 indexed identity, address indexed account);

    constructor(IEntryPoint entryPoint_, bytes32 rootAudience_) {
        entryPoint = entryPoint_;
        rootAudience = rootAudience_;
        owner = msg.sender;
    }

    // One-time setter resolves the deployment cycle: validator binds this
    // factory, while account creation bytecode binds the validator.
    function setGoogleValidator(GoogleJWTValidator validator_) external {
        if (msg.sender != owner) revert NotOwner();
        if (address(googleValidator) != address(0)) revert ValidatorAlreadySet();
        if (address(validator_) == address(0)) revert ValidatorNotSet();
        googleValidator = validator_;
        emit ValidatorSet(address(validator_));
    }

    function createAccount(bytes32 identity) external returns (GoogleAccount account) {
        GoogleJWTValidator validator = googleValidator;
        if (address(validator) == address(0)) revert ValidatorNotSet();
        address predicted = getAddress(identity);
        if (predicted.code.length != 0) return GoogleAccount(payable(predicted));
        account = new GoogleAccount{salt: identity}(identity, entryPoint, validator, address(this), rootAudience);
        emit AccountCreated(identity, address(account));
    }

    function getAddress(bytes32 identity) public view returns (address) {
        GoogleJWTValidator validator = googleValidator;
        if (address(validator) == address(0)) revert ValidatorNotSet();
        bytes memory bytecode = abi.encodePacked(
            type(GoogleAccount).creationCode,
            abi.encode(identity, entryPoint, validator, address(this), rootAudience)
        );
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), identity, keccak256(bytecode)));
        return address(uint160(uint256(hash)));
    }
}
