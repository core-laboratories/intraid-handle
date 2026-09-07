// SPDX-License-Identifier: MIT
pragma solidity ^1.1.2;

import {ModInv} from "smooth-crypto-lib/modular/SCL_modular.sol";
import "smooth-crypto-lib/lib/libSCL_EIP6565.sol";

/// @notice Strict Ed25519 verification built on SmoothCryptoLib's audited core.
/// @dev The public key and both signature halves use their transmitted RFC 8032
///      byte order. Invalid inputs either return false or revert fail-closed.
library Ed25519 {
    uint256 internal constant P =
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
    uint256 internal constant L =
        0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed;
    uint256 internal constant MASK_255 =
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    /// @notice Verify a standard 64-byte Ed25519 signature.
    function verify(
        bytes32 publicKey,
        bytes memory signature,
        bytes memory message
    ) internal returns (bool) {
        if (signature.length != 64) return false;

        bytes32 signatureR;
        bytes32 signatureS;
        assembly {
            signatureR := mload(add(signature, 0x20))
            signatureS := mload(add(signature, 0x40))
        }

        return verify(publicKey, signatureR, signatureS, message);
    }

    /// @notice Verify a standard Ed25519 signature over arbitrary bytes.
    function verify(
        bytes32 publicKey,
        bytes32 signatureR,
        bytes32 signatureS,
        bytes memory message
    ) internal returns (bool) {
        (uint256 wx, uint256 wy, bool ok) = _expand(publicKey);
        if (!ok) return false;

        return _verifyExpanded(
            wx,
            wy,
            uint256(publicKey),
            signatureR,
            signatureS,
            message
        );
    }

    /// @notice Verify standard Ed25519 over a 32-byte application digest.
    /// @dev This is PureEd25519 signing a 32-byte message, not Ed25519ph.
    function verifyDigest(
        bytes32 publicKey,
        bytes32 signatureR,
        bytes32 signatureS,
        bytes32 digest
    ) internal returns (bool) {
        return verify(
            publicKey,
            signatureR,
            signatureS,
            abi.encodePacked(digest)
        );
    }

    /// @notice Verify a standard 64-byte Ed25519 signature over a digest.
    function verifyDigest(
        bytes32 publicKey,
        bytes memory signature,
        bytes32 digest
    ) internal returns (bool) {
        return verify(publicKey, signature, abi.encodePacked(digest));
    }

    /// @dev libsodium-compatible canonical and small-order checks for a
    ///      little-endian encoded Edwards point.
    function _canonicalNonSmallOrder(uint256 leEncoded)
        private
        pure
        returns (bool)
    {
        uint256 y = leEncoded & MASK_255;
        if (y >= P) return false;
        if (y == 0 || y == 1 || y == P - 1) return false;
        if (
            y ==
            0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826
        ) return false;
        if (
            y ==
            0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7
        ) return false;
        return true;
    }

    /// @dev Canonically decompress a raw 32-byte Ed25519 key and convert it to
    ///      the Weierstrass representation expected by SmoothCryptoLib.
    function _expand(bytes32 rawPublicKey)
        private
        returns (uint256 wx, uint256 wy, bool ok)
    {
        uint256 le = _swap256(uint256(rawPublicKey));
        if (!_canonicalNonSmallOrder(le)) return (0, 0, false);

        uint256 sign = le >> 255;
        uint256 y = le & MASK_255;
        uint256 ySquared = mulmod(y, y, P);
        uint256 xSquared = mulmod(
            addmod(ySquared, P - 1, P),
            ModInv(addmod(mulmod(d, ySquared, P), 1, P), P),
            P
        );
        uint256 x = SqrtMod(xSquared);

        if (mulmod(x, x, P) != xSquared) return (0, 0, false);
        if (x == 0 && sign == 1) return (0, 0, false);
        if ((x & 1) != sign) x = P - x;

        (wx, wy) = SCL_EIP6565.Edwards2WeierStrass(x, y);
        ok = true;
    }

    function _verifyExpanded(
        uint256 wx,
        uint256 wy,
        uint256 compressedPublicKey,
        bytes32 signatureR,
        bytes32 signatureS,
        bytes memory message
    ) private view returns (bool) {
        uint256 s = _swap256(uint256(signatureS));
        if (s == 0 || s >= L) return false;

        uint256 r = _swap256(uint256(signatureR));
        if (!_canonicalNonSmallOrder(r)) return false;

        return
            SCL_EIP6565.Verify_LE(
                string(message),
                uint256(signatureR),
                uint256(signatureS),
                [wx, wy, uint256(0), uint256(0), compressedPublicKey]
            );
    }

    function _swap256(uint256 value) private pure returns (uint256 result) {
        for (uint256 i = 0; i < 32; i++) {
            result = (result << 8) | ((value >> (8 * i)) & 0xff);
        }
    }
}
