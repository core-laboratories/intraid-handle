// SPDX-License-Identifier: UNLICENSED
pragma solidity ^1.1.2;

import "spark-std/Test.sol";
import {Ed25519} from "../../src/crypto/Ed25519.sol";

contract Ed25519Harness {
    function verifyPacked(
        bytes32 publicKey,
        bytes calldata signature,
        bytes calldata message
    ) external returns (bool) {
        return Ed25519.verify(publicKey, signature, message);
    }

    function verify(
        bytes32 publicKey,
        bytes32 signatureR,
        bytes32 signatureS,
        bytes calldata message
    ) external returns (bool) {
        return Ed25519.verify(
            publicKey,
            signatureR,
            signatureS,
            message
        );
    }

    function verifyDigest(
        bytes32 publicKey,
        bytes32 signatureR,
        bytes32 signatureS,
        bytes32 digest
    ) external returns (bool) {
        return Ed25519.verifyDigest(
            publicKey,
            signatureR,
            signatureS,
            digest
        );
    }
}

contract Ed25519Test is Test {
    Ed25519Harness private _harness;

    function setUp() public {
        _harness = new Ed25519Harness();
    }

    function testRfc8032EmptyMessage() public {
        assertTrue(
            _harness.verify(
                0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a,
                0xe5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155,
                0x5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b,
                hex""
            )
        );
    }

    function testRfc8032OneByteMessage() public {
        assertTrue(
            _harness.verify(
                0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c,
                0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da,
                0x085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00,
                hex"72"
            )
        );
    }

    function testRfc8032TwoByteMessage() public {
        assertTrue(
            _harness.verify(
                0xfc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025,
                0x6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac,
                0x18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a,
                hex"af82"
            )
        );
    }

    function testVerifyDigest() public {
        assertTrue(
            _harness.verifyDigest(
                0xb49f3a78b1c6a7fca8f3466f33bc0e929f01fba04306c2a7465f46c3759316d9,
                0x04266c033b91c1322ceb3446c901ffcf3cc40c4034e887c9597ca1893ba7330b,
                0xecbbd8b48142ef35c012c6ba51a66df9308cb6268ad6b1e4b03e70102495790b,
                0xa750c232933dc14b1184d86d8b4ce72e16d69744ba69818b6ac33b1d823bb2c3
            )
        );
    }

    function testPackedSignature() public {
        bytes memory signature = abi.encodePacked(
            bytes32(0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da),
            bytes32(0x085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00)
        );

        assertTrue(
            _harness.verifyPacked(
                0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c,
                signature,
                hex"72"
            )
        );
    }

    function testRejectsWrongSignatureLength() public {
        assertFalse(
            _harness.verifyPacked(
                0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c,
                hex"00",
                hex"72"
            )
        );
    }

    function testRejectsChangedMessage() public {
        assertFalse(
            _harness.verify(
                0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c,
                0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da,
                0x085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00,
                hex"73"
            )
        );
    }

    function testRejectsChangedSignature() public {
        assertFalse(
            _harness.verify(
                0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c,
                0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69db,
                0x085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00,
                hex"72"
            )
        );
    }

    function testRejectsNonCanonicalS() public {
        assertFalse(
            _harness.verify(
                0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c,
                0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da,
                0xedd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010,
                hex"72"
            )
        );
    }

    function testRejectsSmallOrderPublicKey() public {
        assertFalse(
            _harness.verify(
                0x0100000000000000000000000000000000000000000000000000000000000000,
                0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da,
                0x085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00,
                hex"72"
            )
        );
    }
}
