// SPDX-License-Identifier: UNLICENSED
pragma solidity ^1.1.2;

import "spark-std/Test.sol";
import "../src/IdentityLinkRegistry.sol";
import "../lib/core-openzeppelin-contracts/src/proxy/ERC1967/ERC1967Proxy.sol";
import "../lib/core-openzeppelin-contracts-upgradeable/src/utils/ChecksumUpgradeable.sol";

contract IdentityLinkRegistryV2 is IdentityLinkRegistry {
    function version() external pure returns (uint256) {
        return 2;
    }
}

contract RevertingTreasury {
    receive() external payable {
        revert("no deposits");
    }
}

contract IdentityLinkRegistryTest is Test {
    IdentityLinkRegistry private implementation;
    IdentityLinkRegistry private registry;

    address payable private treasury;
    address private alice;
    address private bob;

    function setUp() public {
        treasury = payable(makeAddr("treasury"));
        alice = makeAddr("alice");
        bob = makeAddr("bob");

        implementation = new IdentityLinkRegistry();
        bytes memory initializer = abi.encodeWithSelector(IdentityLinkRegistry.initialize.selector, treasury);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initializer);
        registry = IdentityLinkRegistry(address(proxy));

        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    function testInitialization() public {
        assertEq(registry.owner(), address(this));
        assertEq(registry.treasury(), treasury);
        assertEq(registry.MIN_NAME_LENGTH(), 3);
        assertEq(registry.MAX_NAME_LENGTH(), 32);
        assertEq(registry.MAX_DISCOVERY_POINTER_LENGTH(), 512);
    }

    function testImplementationCannotBeInitialized() public {
        vm.expectRevert(bytes("Initializable: contract is already initialized"));
        implementation.initialize(treasury);
    }

    function testProxyCannotBeInitializedTwice() public {
        vm.expectRevert(bytes("Initializable: contract is already initialized"));
        registry.initialize(treasury);
    }

    function testInitializerRejectsRealZeroTreasury() public {
        IdentityLinkRegistry anotherImplementation = new IdentityLinkRegistry();
        bytes memory initializer = abi.encodeWithSelector(IdentityLinkRegistry.initialize.selector, payable(address(0)));

        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.InvalidTreasury.selector, address(0)));
        new ERC1967Proxy(address(anotherImplementation), initializer);
    }

    function testInitializerRejectsChecksummedZeroTreasury() public {
        IdentityLinkRegistry anotherImplementation = new IdentityLinkRegistry();
        address coreZero = ChecksumUpgradeable.zeroAddress();
        bytes memory initializer = abi.encodeWithSelector(IdentityLinkRegistry.initialize.selector, payable(coreZero));

        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.InvalidTreasury.selector, coreZero));
        new ERC1967Proxy(address(anotherImplementation), initializer);
    }

    function testNormalizeNameLowercasesASCII() public {
        assertEq(registry.normalizeName("Alice_123"), "alice_123");
        assertEq(registry.hashName("ALICE"), registry.hashName("alice"));
    }

    function testNormalizeNameRejectsInvalidLength() public {
        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.InvalidNameLength.selector, 2));
        registry.normalizeName("ab");

        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.InvalidNameLength.selector, 33));
        registry.normalizeName("abcdefghijklmnopqrstuvwxyz1234567");
    }

    function testNormalizeNameRejectsInvalidCharacters() public {
        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.InvalidNameCharacter.selector, 3, bytes1("-")));
        registry.normalizeName("abc-def");

        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.InvalidNameCharacter.selector, 3, bytes1(".")));
        registry.normalizeName("abc.def");
    }

    function testNormalizeNameRejectsInvalidSeparators() public {
        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.InvalidNameSeparator.selector, 0));
        registry.normalizeName("_alice");

        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.InvalidNameSeparator.selector, 5));
        registry.normalizeName("alice_");

        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.InvalidNameSeparator.selector, 6));
        registry.normalizeName("alice__bob");
    }

    function testRegistrationFeeSchedule() public {
        assertEq(registry.registrationFee("abc"), 10 ether);
        assertEq(registry.registrationFee("abcd"), 5 ether);
        assertEq(registry.registrationFee("abcde"), 5 ether);
        assertEq(registry.registrationFee("abcdef"), 2 ether);
        assertEq(registry.registrationFee("abcdefg"), 2 ether);
        assertEq(registry.registrationFee("abcdefgh"), 1 ether);
    }

    function testInitialReservedNames() public {
        assertTrue(registry.isReservedName("ADMIN"));
        assertTrue(registry.isReservedName("support"));
        assertTrue(registry.isReservedName("tone"));
        assertTrue(registry.isReservedName("core"));
        assertTrue(registry.isReservedName("invite"));
        assertTrue(registry.isReservedName("security"));
        assertTrue(registry.isReservedName("official"));
    }

    function testRegisterNameStoresCanonicalBinding() public {
        uint64 timestamp = 1_800_000_000;
        vm.warp(timestamp);
        bytes32 expectedHash = registry.hashName("alice_123");

        vm.prank(alice);
        bytes32 actualHash = registry.registerName{value: 1 ether}("Alice_123");

        assertEq(actualHash, expectedHash);
        IIdentityLinkRegistry.NameRecord memory record = registry.resolveName(expectedHash);
        assertEq(record.owner, alice);
        assertEq(record.generation, 1);
        assertEq(record.createdAt, timestamp);
        assertEq(record.updatedAt, timestamp);
        assertEq(uint8(record.status), uint8(IIdentityLinkRegistry.NameStatus.Active));
        assertEq(registry.getPrimaryName(alice), expectedHash);
        assertEq(address(registry).balance, 1 ether);
    }

    function testRegisterNameRejectsIncorrectFee() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.IncorrectRegistrationFee.selector, 10 ether, 9 ether));
        registry.registerName{value: 9 ether}("abc");

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.IncorrectRegistrationFee.selector, 10 ether, 11 ether));
        registry.registerName{value: 11 ether}("abc");
    }

    function testRegisterNameRejectsReservedName() public {
        bytes32 nameHash = registry.hashName("admin");
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.ReservedName.selector, nameHash));
        registry.registerName{value: 5 ether}("ADMIN");
    }

    function testOneActiveNamePerIdentity() public {
        _register(alice, "alice", 5 ether);
        bytes32 currentHash = registry.hashName("alice");

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IdentityLinkRegistry.IdentityAlreadyHasName.selector, alice, currentHash)
        );
        registry.registerName{value: 5 ether}("other");
    }

    function testNameCannotHaveTwoOwners() public {
        _register(alice, "alice", 5 ether);
        bytes32 nameHash = registry.hashName("alice");

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.NameUnavailable.selector, nameHash));
        registry.registerName{value: 5 ether}("ALICE");
    }

    function testOnlyCurrentOwnerCanRemoveName() public {
        _register(alice, "alice", 5 ether);
        bytes32 nameHash = registry.hashName("alice");

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.NotNameOwner.selector, nameHash, bob));
        registry.removeName(nameHash);
    }

    function testRemovedNameIsImmediatelyReusableAndIncrementsGeneration() public {
        uint64 firstTimestamp = 1_800_000_000;
        vm.warp(firstTimestamp);
        _register(alice, "alice", 5 ether);
        bytes32 nameHash = registry.hashName("alice");

        vm.warp(firstTimestamp + 100);
        vm.prank(alice);
        registry.removeName(nameHash);

        IIdentityLinkRegistry.NameRecord memory removed = registry.resolveName(nameHash);
        assertEq(removed.owner, address(0));
        assertEq(removed.generation, 1);
        assertEq(removed.updatedAt, firstTimestamp + 100);
        assertEq(uint8(removed.status), uint8(IIdentityLinkRegistry.NameStatus.Available));
        assertEq(registry.getPrimaryName(alice), bytes32(0));

        vm.warp(firstTimestamp + 200);
        _register(bob, "ALICE", 5 ether);

        IIdentityLinkRegistry.NameRecord memory reused = registry.resolveName(nameHash);
        assertEq(reused.owner, bob);
        assertEq(reused.generation, 2);
        assertEq(reused.createdAt, firstTimestamp + 200);
        assertEq(reused.updatedAt, firstTimestamp + 200);
        assertEq(registry.getPrimaryName(bob), nameHash);
    }

    function testSetIdentityRecordComputesHashAndIncrementsRevision() public {
        bytes memory firstPointer = hex"0a20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        bytes32 firstProfileHash = keccak256("profile-1");

        vm.warp(1_800_000_000);
        vm.prank(alice);
        (bytes32 firstHash, uint64 firstRevision) = registry.setIdentityRecord(firstPointer, firstProfileHash);

        assertEq(firstHash, keccak256(firstPointer));
        assertEq(firstRevision, 1);
        IIdentityLinkRegistry.IdentityRecord memory firstRecord = registry.resolveIdentity(alice);
        assertEq(firstRecord.chatLinkHash, keccak256(firstPointer));
        assertEq(firstRecord.discoveryPointer, firstPointer);
        assertEq(firstRecord.profileHash, firstProfileHash);
        assertEq(firstRecord.revision, 1);
        assertEq(firstRecord.updatedAt, 1_800_000_000);

        bytes memory secondPointer = hex"01020304";
        bytes32 secondProfileHash = keccak256("profile-2");
        vm.warp(1_800_000_100);
        vm.prank(alice);
        registry.setIdentityRecord(secondPointer, secondProfileHash);

        IIdentityLinkRegistry.IdentityRecord memory secondRecord = registry.resolveIdentity(alice);
        assertEq(secondRecord.chatLinkHash, keccak256(secondPointer));
        assertEq(secondRecord.discoveryPointer, secondPointer);
        assertEq(secondRecord.profileHash, secondProfileHash);
        assertEq(secondRecord.revision, 2);
        assertEq(secondRecord.updatedAt, 1_800_000_100);
    }

    function testIdentityRecordsAreScopedToCaller() public {
        vm.prank(alice);
        registry.setIdentityRecord(hex"01", bytes32(uint256(1)));

        vm.prank(bob);
        registry.setIdentityRecord(hex"02", bytes32(uint256(2)));

        assertEq(registry.resolveIdentity(alice).discoveryPointer, hex"01");
        assertEq(registry.resolveIdentity(bob).discoveryPointer, hex"02");
    }

    function testSetIdentityRecordRejectsInvalidPointerLength() public {
        vm.prank(alice);
        vm.expectRevert(IdentityLinkRegistry.EmptyDiscoveryPointer.selector);
        registry.setIdentityRecord(new bytes(0), bytes32(0));

        bytes memory oversizedPointer = new bytes(513);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.DiscoveryPointerTooLong.selector, 513));
        registry.setIdentityRecord(oversizedPointer, bytes32(0));
    }

    function testOwnerCanManageUnclaimedReservedName() public {
        registry.setReservedName("founder", true);
        assertTrue(registry.isReservedName("FOUNDER"));

        registry.setReservedName("founder", false);
        assertFalse(registry.isReservedName("founder"));
        _register(alice, "founder", 2 ether);
    }

    function testCannotReserveActiveName() public {
        _register(alice, "alice", 5 ether);
        bytes32 nameHash = registry.hashName("alice");

        vm.expectRevert(abi.encodeWithSelector(IdentityLinkRegistry.NameIsActive.selector, nameHash));
        registry.setReservedName("alice", true);
    }

    function testNonOwnerCannotManageReservedNamesOrTreasury() public {
        vm.startPrank(alice);
        vm.expectRevert(bytes("Ownable: caller is not the owner"));
        registry.setReservedName("founder", true);

        vm.expectRevert(bytes("Ownable: caller is not the owner"));
        registry.setTreasury(payable(bob));
        vm.stopPrank();
    }

    function testOwnerCanUpdateTreasuryAndWithdrawFees() public {
        _register(alice, "alice", 5 ether);
        uint256 bobBalanceBefore = bob.balance;

        registry.setTreasury(payable(bob));
        registry.withdrawFees();

        assertEq(registry.treasury(), bob);
        assertEq(address(registry).balance, 0);
        assertEq(bob.balance, bobBalanceBefore + 5 ether);
    }

    function testWithdrawRejectsEmptyBalance() public {
        vm.expectRevert(IdentityLinkRegistry.NoFeesToWithdraw.selector);
        registry.withdrawFees();
    }

    function testWithdrawRevertsWhenTreasuryRejectsPayment() public {
        RevertingTreasury rejectingTreasury = new RevertingTreasury();
        registry.setTreasury(payable(address(rejectingTreasury)));
        _register(alice, "alice", 5 ether);

        vm.expectRevert(bytes("Address: unable to send value, recipient may have reverted"));
        registry.withdrawFees();
        assertEq(address(registry).balance, 5 ether);
    }

    function testOnlyOwnerCanUpgradeAndStateIsPreserved() public {
        _register(alice, "alice", 5 ether);
        bytes32 nameHash = registry.hashName("alice");
        IdentityLinkRegistryV2 nextImplementation = new IdentityLinkRegistryV2();

        vm.prank(alice);
        vm.expectRevert(bytes("Ownable: caller is not the owner"));
        registry.upgradeTo(address(nextImplementation));

        registry.upgradeTo(address(nextImplementation));

        IdentityLinkRegistryV2 upgraded = IdentityLinkRegistryV2(address(registry));
        assertEq(upgraded.version(), 2);
        assertEq(upgraded.resolveName(nameHash).owner, alice);
        assertEq(upgraded.getPrimaryName(alice), nameHash);
        assertEq(upgraded.treasury(), treasury);
    }

    function _register(address account, string memory name, uint256 fee) internal {
        vm.prank(account);
        registry.registerName{value: fee}(name);
    }
}
