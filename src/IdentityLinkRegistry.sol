// SPDX-License-Identifier: MIT
pragma solidity ^1.1.2;

import "./interfaces/IIdentityLinkRegistry.sol";
import "../lib/core-openzeppelin-contracts-upgradeable/src/access/OwnableUpgradeable.sol";
import "../lib/core-openzeppelin-contracts-upgradeable/src/proxy/utils/UUPSUpgradeable.sol";
import "../lib/core-openzeppelin-contracts-upgradeable/src/security/ReentrancyGuardUpgradeable.sol";
import "../lib/core-openzeppelin-contracts-upgradeable/src/utils/AddressUpgradeable.sol";
import "../lib/core-openzeppelin-contracts-upgradeable/src/utils/ChecksumUpgradeable.sol";

contract IdentityLinkRegistry is
    IIdentityLinkRegistry,
    OwnableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable
{
    using AddressUpgradeable for address payable;

    uint256 public constant MIN_NAME_LENGTH = 3;
    uint256 public constant MAX_NAME_LENGTH = 32;
    uint256 public constant MAX_DISCOVERY_POINTER_LENGTH = 512;

    mapping(bytes32 => NameRecord) private _names;
    mapping(address => bytes32) private _primaryNames;
    mapping(address => IdentityRecord) private _identities;
    mapping(bytes32 => bool) private _reservedNames;

    address payable public treasury;

    error InvalidNameLength(uint256 length);
    error InvalidNameCharacter(uint256 index, bytes1 character);
    error InvalidNameSeparator(uint256 index);
    error ReservedName(bytes32 nameHash);
    error NameUnavailable(bytes32 nameHash);
    error IdentityAlreadyHasName(address identity, bytes32 nameHash);
    error IncorrectRegistrationFee(uint256 expected, uint256 received);
    error NotNameOwner(bytes32 nameHash, address caller);
    error EmptyDiscoveryPointer();
    error DiscoveryPointerTooLong(uint256 length);
    error InvalidTreasury(address treasuryAddress);
    error NameIsActive(bytes32 nameHash);
    error NoFeesToWithdraw();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address payable initialTreasury) external initializer {
        _validateTreasury(initialTreasury);

        __Ownable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        treasury = initialTreasury;
        emit TreasuryUpdated(address(0), initialTreasury);

        _reserveInitialName("admin");
        _reserveInitialName("support");
        _reserveInitialName("tone");
        _reserveInitialName("core");
        _reserveInitialName("invite");
        _reserveInitialName("id");
        _reserveInitialName("api");
        _reserveInitialName("security");
        _reserveInitialName("official");
    }

    function registerName(string calldata name) external payable override returns (bytes32 nameHash_) {
        string memory canonicalName = _normalizeName(name);
        nameHash_ = keccak256(bytes(canonicalName));

        if (_reservedNames[nameHash_]) revert ReservedName(nameHash_);

        NameRecord storage record = _names[nameHash_];
        if (record.status == NameStatus.Active) revert NameUnavailable(nameHash_);

        bytes32 currentNameHash = _primaryNames[msg.sender];
        if (currentNameHash != bytes32(0)) revert IdentityAlreadyHasName(msg.sender, currentNameHash);

        uint256 requiredFee = _registrationFee(bytes(canonicalName).length);
        if (msg.value != requiredFee) revert IncorrectRegistrationFee(requiredFee, msg.value);

        uint64 timestamp = uint64(block.timestamp);
        uint64 nextGeneration = record.generation + 1;

        record.owner = msg.sender;
        record.generation = nextGeneration;
        record.createdAt = timestamp;
        record.updatedAt = timestamp;
        record.status = NameStatus.Active;
        _primaryNames[msg.sender] = nameHash_;

        emit NameRegistered(nameHash_, canonicalName, msg.sender, nextGeneration, msg.value);
    }

    function removeName(bytes32 nameHash_) external override {
        NameRecord storage record = _names[nameHash_];
        if (record.status != NameStatus.Active || record.owner != msg.sender) {
            revert NotNameOwner(nameHash_, msg.sender);
        }

        uint64 generation = record.generation;
        record.owner = address(0);
        record.updatedAt = uint64(block.timestamp);
        record.status = NameStatus.Available;
        delete _primaryNames[msg.sender];

        emit NameRemoved(nameHash_, msg.sender, generation);
    }

    function registrationFee(string calldata name) external pure override returns (uint256 feeXCB) {
        string memory canonicalName = _normalizeName(name);
        return _registrationFee(bytes(canonicalName).length);
    }

    function normalizeName(string calldata name) external pure override returns (string memory canonicalName) {
        return _normalizeName(name);
    }

    function hashName(string calldata name) external pure override returns (bytes32 nameHash_) {
        return keccak256(bytes(_normalizeName(name)));
    }

    function setIdentityRecord(bytes calldata discoveryPointer, bytes32 profileHash)
        external
        override
        returns (bytes32 chatLinkHash, uint64 revision)
    {
        uint256 pointerLength = discoveryPointer.length;
        if (pointerLength == 0) revert EmptyDiscoveryPointer();
        if (pointerLength > MAX_DISCOVERY_POINTER_LENGTH) revert DiscoveryPointerTooLong(pointerLength);

        IdentityRecord storage record = _identities[msg.sender];
        chatLinkHash = keccak256(discoveryPointer);
        revision = record.revision + 1;

        record.chatLinkHash = chatLinkHash;
        record.discoveryPointer = discoveryPointer;
        record.profileHash = profileHash;
        record.revision = revision;
        record.updatedAt = uint64(block.timestamp);

        emit IdentityRecordUpdated(msg.sender, chatLinkHash, profileHash, revision);
    }

    function resolveName(bytes32 nameHash_) external view override returns (NameRecord memory record) {
        return _names[nameHash_];
    }

    function resolveIdentity(address identity) external view override returns (IdentityRecord memory record) {
        return _identities[identity];
    }

    function getPrimaryName(address identity) external view override returns (bytes32 nameHash_) {
        return _primaryNames[identity];
    }

    function isReservedName(string calldata name) external view override returns (bool) {
        return _reservedNames[keccak256(bytes(_normalizeName(name)))];
    }

    function isReservedNameHash(bytes32 nameHash_) external view override returns (bool) {
        return _reservedNames[nameHash_];
    }

    function setReservedName(string calldata name, bool reserved) external onlyOwner {
        string memory canonicalName = _normalizeName(name);
        bytes32 nameHash_ = keccak256(bytes(canonicalName));

        if (reserved && _names[nameHash_].status == NameStatus.Active) revert NameIsActive(nameHash_);

        _reservedNames[nameHash_] = reserved;
        emit ReservedNameUpdated(nameHash_, canonicalName, reserved);
    }

    function setTreasury(address payable newTreasury) external onlyOwner {
        _validateTreasury(newTreasury);
        address previousTreasury = treasury;
        treasury = newTreasury;
        emit TreasuryUpdated(previousTreasury, newTreasury);
    }

    function withdrawFees() external onlyOwner nonReentrant {
        uint256 amount = address(this).balance;
        if (amount == 0) revert NoFeesToWithdraw();

        address payable recipient = treasury;
        recipient.sendValue(amount);
        emit FeesWithdrawn(recipient, amount);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function _normalizeName(string memory name) internal pure returns (string memory canonicalName) {
        bytes memory value = bytes(name);
        uint256 length = value.length;
        if (length < MIN_NAME_LENGTH || length > MAX_NAME_LENGTH) revert InvalidNameLength(length);

        for (uint256 i = 0; i < length; ++i) {
            uint8 character = uint8(value[i]);

            if (character >= 65 && character <= 90) {
                character += 32;
                value[i] = bytes1(character);
            }

            bool isLetter = character >= 97 && character <= 122;
            bool isDigit = character >= 48 && character <= 57;
            bool isSeparator = character == 95;
            if (!isLetter && !isDigit && !isSeparator) revert InvalidNameCharacter(i, value[i]);

            if (isSeparator && (i == 0 || i == length - 1 || value[i - 1] == bytes1("_"))) {
                revert InvalidNameSeparator(i);
            }
        }

        return string(value);
    }

    function _registrationFee(uint256 length) internal pure returns (uint256) {
        if (length <= 3) return 10 ether;
        if (length <= 5) return 5 ether;
        if (length <= 7) return 2 ether;
        return 1 ether;
    }

    function _reserveInitialName(string memory name) internal {
        bytes32 nameHash_ = keccak256(bytes(name));
        _reservedNames[nameHash_] = true;
        emit ReservedNameUpdated(nameHash_, name, true);
    }

    function _validateTreasury(address treasuryAddress) internal view {
        if (treasuryAddress == address(0) || treasuryAddress == ChecksumUpgradeable.zeroAddress()) {
            revert InvalidTreasury(treasuryAddress);
        }
    }

    uint256[44] private __gap;
}
