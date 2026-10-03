# fabric-lib-go BCCSP PQC

This module provides a separate BCCSP implementation backed by
[liboqs-go](https://github.com/open-quantum-safe/liboqs-go). It supports the
standardized ML-DSA signature algorithms and ML-KEM key encapsulation
algorithms exposed by liboqs 0.16.

## Native prerequisites

liboqs-go is a cgo binding. Install liboqs, a C compiler, `pkg-config`, and
the liboqs-go pkg-config file before building this module. The upstream
installation instructions are available in the liboqs-go repository.

```sh
export PKG_CONFIG_PATH=/path/to/liboqs-go/.config
go test ./...
```

The module uses `replace github.com/hyperledger/fabric-lib-go => ..` for local
development. Remove that replace directive and use a published parent module
version when consuming this package externally.

## API notes

`CSP` implements the parent repository's `bccsp.BCCSP` interface. ML-DSA is
available through `KeyGen`, `Sign`, and `Verify`. ML-KEM is exposed through the
additional `KEM` interface because KEM encapsulation returns both ciphertext
and a shared secret; it is not conventional public-key encryption.

The existing Fabric `bccsp/signer` helper parses public keys with Go's
`x509.ParsePKIXPublicKey`. Go and standard Fabric X.509 profiles do not yet
provide ML-DSA/ML-KEM certificate support, so this module supplies raw PQC
key bytes and BCCSP operations but does not claim drop-in compatibility with
an existing ECDSA-based Fabric MSP certificate profile.

Private-key imports require the matching public key in
`PrivateKeyImportOpts.PublicKey`, because liboqs does not expose a public-key
derivation operation from an exported secret key.