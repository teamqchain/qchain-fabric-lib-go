# fabric-lib-go BCCSP PQC

Package `bccsp-pqc` provides a post-quantum BCCSP implementation. ML-DSA-44,
ML-DSA-65 and ML-DSA-87 signatures use Go's `crypto/mldsa`. ML-KEM-512,
ML-KEM-768 and ML-KEM-1024 key encapsulation use
[liboqs-go](https://github.com/open-quantum-safe/liboqs-go) (liboqs 0.16),
which also handles legacy seedless ML-DSA keys.

## Native prerequisites

liboqs-go is a cgo binding. Install liboqs, a C compiler, `pkg-config`, and
the liboqs-go pkg-config file before building this package. The upstream
installation instructions are available in the liboqs-go repository.

```sh
export PKG_CONFIG_PATH=/path/to/liboqs-go/.config
go test ./bccsp-pqc/
```

The package is part of the `github.com/hyperledger/fabric-lib-go` module and
has no `go.mod` of its own.

## API notes

`CSP` implements the parent repository's `bccsp.BCCSP` interface. ML-DSA is
available through `KeyGen`, `Sign`, and `Verify`. ML-KEM is exposed through the
additional `KEM` interface because KEM encapsulation returns both ciphertext
and a shared secret; it is not conventional public-key encryption.

Go 1.27's `crypto/x509` parses and creates ML-DSA certificates, CSRs and
PKIX public keys, so the Fabric `bccsp/signer` helper gives a `crypto.Signer`
over this CSP that can issue them. An MSP accepts ML-DSA certificates only if
it allows the ML-DSA public-key algorithm, which upstream Fabric does not.
ML-KEM keys have no certificate role.

Private-key imports require the matching public key in
`PrivateKeyImportOpts.PublicKey`. For a seed, it must equal the public key
derived from the seed. A legacy expanded liboqs secret has no seed to derive
it from, so the given public key is used as is.

An ML-DSA seed key keeps its expanded `crypto/mldsa` private key (about
197 KB for ML-DSA-44) for as long as the key object lives, so `Sign` does not
rebuild it from the seed on every call. Go's `mldsa.PrivateKey` cannot be
zeroed, so only the seed copies this package makes are cleared.

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
is already in the keystore, as `<ski>_sk`, as a legacy `<ski>.pqc`, or under
another file name found by the scan (such as `priv_sk`).
