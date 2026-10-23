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

## Use of liboqs

ML-DSA keys are generated, stored, signed with and verified using Go's
`crypto/mldsa`. liboqs is used for ML-KEM and for legacy seedless ML-DSA keys
only: an imported expanded liboqs secret, or one in a `.pqc` file from an
earlier version, has no seed, so liboqs validates it at import and signs with
it.

## Keystore

`FileKeyStore` names files by SKI (hex of SHA-256 over the raw public key):

| Key | File | Format |
|---|---|---|
| ML-DSA private | `<ski>_sk` | PEM `PRIVATE KEY`, PKCS#8 holding the FIPS 204 seed (same as cryptogen) |
| ML-DSA public | `<ski>_pk` | PEM `PUBLIC KEY`, PKIX |
| ML-KEM private or public | `<ski>.pqc` | JSON, AES-GCM encrypted when a password is set |

ML-KEM keys stay in `.pqc` because Go's PKCS#8 has no ML-KEM encoding.

`GetKey` looks up `<ski>_sk`, then `<ski>_pk`, then `<ski>.pqc`, and finally
scans the directory for a PKCS#8 ML-DSA private key under any file name, such
as cryptogen's `priv_sk`. `.pqc` files written for ML-DSA keys by earlier
versions still load, but ML-DSA keys are never written in that format.

Storing an ML-DSA private key fails when the keystore has a password, because
the PEM file is not encrypted; ML-DSA public keys are written to `<ski>_pk`
unencrypted either way. Storing an ML-DSA private key that has no seed (an
expanded liboqs secret) also fails; import such keys with `Temporary: true`
to keep them in memory only. A public key is not written when its private key
is already stored as `<ski>_sk` or as a legacy `<ski>.pqc`.