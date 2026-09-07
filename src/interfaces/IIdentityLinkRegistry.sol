// SPDX-License-Identifier: MIT
pragma solidity ^1.1.2;

interface IIdentityLinkRegistry {
    enum NameStatus {
        Available,
        Active
    }

    struct NameRecord {
        address owner;
        uint64 generation;
        uint64 createdAt;
        uint64 updatedAt;
        NameStatus status;
    }

    struct IdentityRecord {
        bytes32 chatLinkHash;
        bytes discoveryPointer;
        bytes32 profileHash;
        uint64 revision;
        uint64 updatedAt;
    }

    event NameRegistered(
        bytes32 indexed nameHash,
        string name,
        address indexed owner,
        uint64 generation,
        uint256 feePaid
    );
    event NameRemoved(bytes32 indexed nameHash, address indexed owner, uint64 generation);
    event IdentityRecordUpdated(
        address indexed identity,
        bytes32 indexed chatLinkHash,
        bytes32 profileHash,
        uint64 revision
    );
    event ReservedNameUpdated(bytes32 indexed nameHash, string name, bool reserved);
    event TreasuryUpdated(address indexed previousTreasury, address indexed newTreasury);
    event FeesWithdrawn(address indexed treasury, uint256 amount);

    function registerName(string calldata name) external payable returns (bytes32 nameHash);

    function removeName(bytes32 nameHash) external;

    function registrationFee(string calldata name) external pure returns (uint256 feeXCB);

    function normalizeName(string calldata name) external pure returns (string memory canonicalName);

    function hashName(string calldata name) external pure returns (bytes32 nameHash);

    function setIdentityRecord(bytes calldata discoveryPointer, bytes32 profileHash)
        external
        returns (bytes32 chatLinkHash, uint64 revision);

    function resolveName(bytes32 nameHash) external view returns (NameRecord memory record);

    function resolveIdentity(address identity) external view returns (IdentityRecord memory record);

    function getPrimaryName(address identity) external view returns (bytes32 nameHash);

    function isReservedName(string calldata name) external view returns (bool);

    function isReservedNameHash(bytes32 nameHash) external view returns (bool);
}
