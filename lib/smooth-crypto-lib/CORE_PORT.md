# SmoothCryptoLib Core port

This directory contains the minimal Solidity dependency set needed by the
Ed25519 verifier in `src/crypto/Ed25519.sol`.

- Upstream: https://github.com/get-smooth/crypto-lib
- Pinned upstream commit: `d714e9824e2e2e44be3c8fd498e0de651ddc9425`
- Upstream license: MIT, retained in `LICENSE`
- Local changes: Solidity pragmas were changed from
  `>=0.8.19 <0.9.0` to Core Ylem `^1.1.2`, and the unsupported
  `assembly ("memory-safe")` annotation was reduced to `assembly`. SHA-384/512
  return words are assembled with shifts because Ylem rejects direct
  `bytes memory` to fixed-bytes casts.
- The one `@solidity/` source import was made relative so the vendored subset
  does not require a project-wide remapping.
- The seven public functions in `libSCL_EIP6565.sol` were made `internal`,
  following the Exura wrapper's audited-core pin. This removes external
  library linking and makes the consuming verifier artifact self-contained.

The strict compressed-key and signature checks in the wrapper are adapted
from ExuraLabs/cip8-verifier's `src/Ed25519.sol`, which vendors the same SCL
commit and tests its acceptance set against libsodium.

- Wrapper reference: https://github.com/ExuraLabs/cip8-verifier
- Wrapper license: MIT

This is currently a Core proof of concept and must not be treated as audited
for Core until the port is independently reviewed and tested on the target
network.
