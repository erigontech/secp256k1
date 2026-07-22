# secp256k1

Extraction of the secp256k1 library from go-ethereum, wrapping the
[bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1) C library
(vendored under `libsecp256k1/`) for use as a Go module.

## Versioning

The module version (`vX.Y.Z`) follows Go semantic import versioning for this
**wrapper** and is independent of the bundled **libsecp256k1** release. Do not
expect the two numbers to relate; see the mapping below.

| module tag | bundled libsecp256k1 |
|------------|----------------------|
| v1.3.0     | 0.7.1                |
| v1.2.0     | 0.6.0                |
| v1.1.0     | pre-0.6 amalgamation |
| v1.0.0     | pre-0.6 amalgamation |

Per-release notes live on the [Releases](../../releases) page.
