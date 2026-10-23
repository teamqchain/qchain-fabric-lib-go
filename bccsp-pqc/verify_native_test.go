/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pqc

import (
	"crypto/mldsa"
	"crypto/sha256"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
)

// mspDigest mirrors the Fabric MSP convention: ML-DSA signs SHA-256(msg).
func mspDigest(msg string) []byte {
	d := sha256.Sum256([]byte(msg))
	return d[:]
}

// verifyKeys returns the signing key and every public-key form of it: the
// private key itself, PublicKey(), raw, PKIX and X.509 imports, and keys
// reloaded from <ski>_sk and <ski>_pk.
func verifyKeys(t *testing.T, name string) (*CSP, bccsp.Key, map[string]bccsp.Key) {
	t.Helper()
	skDir, pkDir := t.TempDir(), t.TempDir()
	csp, err := NewWithFileKeyStore(skDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := csp.KeyGen(&KeyGenOpts{AlgorithmName: name})
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := priv.PublicKey()
	der, _ := pub.Bytes()
	raw := append([]byte(nil), priv.(*key).public...)
	eph := &PublicKeyImportOpts{AlgorithmName: name, Temporary: true}
	must := func(k bccsp.Key, err error) bccsp.Key {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	keys := map[string]bccsp.Key{
		"private":     priv,
		"PublicKey()": pub,
		"raw":         must(csp.KeyImport(raw, eph)),
		"PKIX":        must(csp.KeyImport(der, eph)),
		"X.509":       must(csp.KeyImport(selfSignedCert(t, csp, priv), &bccsp.X509PublicKeyImportOpts{Temporary: true})),
	}
	fromSK, _ := NewWithFileKeyStore(skDir, nil)
	keys["_sk reload"] = must(fromSK.GetKey(priv.SKI()))
	pkStore, _ := NewWithFileKeyStore(pkDir, nil)
	must(pkStore.KeyImport(der, &PublicKeyImportOpts{AlgorithmName: name}))
	fromPK, _ := NewWithFileKeyStore(pkDir, nil)
	keys["_pk reload"] = must(fromPK.GetKey(priv.SKI()))
	if keys["_pk reload"].Private() {
		t.Fatal("_pk reload returned a private key")
	}
	return csp, priv, keys
}

func TestMLDSAVerifyAcceptsAllPublicKeyForms(t *testing.T) {
	for _, set := range mldsaSets {
		t.Run(set.name, func(t *testing.T) {
			csp, priv, keys := verifyKeys(t, set.name)
			digest := mspDigest("transaction proposal")
			sig, err := csp.Sign(priv, digest, nil)
			if err != nil {
				t.Fatal(err)
			}
			for form, k := range keys {
				if ok, err := csp.Verify(k, sig, digest, nil); err != nil || !ok {
					t.Fatalf("%s: Sign's signature does not verify (ok=%v, err=%v)", form, ok, err)
				}
			}
			// Sign and Verify treat the digest as the message: stdlib
			// verification over the same digest succeeds, over the
			// original message it does not.
			pub, _ := mldsa.NewPublicKey(set.params, priv.(*key).public)
			if err := mldsa.Verify(pub, digest, sig, nil); err != nil {
				t.Fatalf("stdlib does not verify Sign's signature over the digest: %v", err)
			}
			if err := mldsa.Verify(pub, []byte("transaction proposal"), sig, nil); err == nil {
				t.Fatal("signature verified over the unhashed message; Sign must not hash again")
			}
		})
	}
}

func TestMLDSAVerifyRejectsBadSignatures(t *testing.T) {
	for _, set := range mldsaSets {
		t.Run(set.name, func(t *testing.T) {
			csp, priv, keys := verifyKeys(t, set.name)
			digest := mspDigest("transaction proposal")
			sig, err := csp.Sign(priv, digest, nil)
			if err != nil {
				t.Fatal(err)
			}
			other, _ := csp.KeyGen(&KeyGenOpts{AlgorithmName: set.name, Temporary: true})
			otherSig, _ := csp.Sign(other, digest, nil)

			flipped := func(b []byte, i int) []byte {
				c := append([]byte(nil), b...)
				c[i] ^= 0x01
				return c
			}
			cases := map[string]struct{ sig, digest []byte }{
				"tampered signature (first byte)": {flipped(sig, 0), digest},
				"tampered signature (last byte)":  {flipped(sig, len(sig)-1), digest},
				"tampered digest":                 {sig, flipped(digest, 0)},
				"different message":               {sig, mspDigest("another proposal")},
				"truncated signature":             {sig[:len(sig)-1], digest},
				"extended signature":              {append(append([]byte(nil), sig...), 0), digest},
				"empty signature":                 {nil, digest},
				"signature from a different key":  {otherSig, digest},
			}
			for form, k := range keys {
				for name, c := range cases {
					ok, err := csp.Verify(k, c.sig, c.digest, nil)
					if ok || err != nil {
						t.Fatalf("%s / %s: got (%v, %v), want (false, nil)", form, name, ok, err)
					}
				}
			}
		})
	}
}

type notPQCKey struct{}

func (notPQCKey) Bytes() ([]byte, error)        { return nil, nil }
func (notPQCKey) SKI() []byte                   { return nil }
func (notPQCKey) Symmetric() bool               { return false }
func (notPQCKey) Private() bool                 { return false }
func (notPQCKey) PublicKey() (bccsp.Key, error) { return nil, nil }

func TestMLDSAVerifyErrorsOnInvalidKeys(t *testing.T) {
	csp, err := NewWithFileKeyStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	kem, _ := csp.KeyGen(&KeyGenOpts{AlgorithmName: MLKEM768, Temporary: true})
	var typedNil *key
	cases := map[string]bccsp.Key{
		"nil key":             nil,
		"typed nil *key":      typedNil,
		"non-PQC key type":    notPQCKey{},
		"ML-KEM key":          kem,
		"malformed ML-DSA-44": &key{algorithm: MLDSA44, public: []byte{1, 2, 3}},
		"empty ML-DSA-65":     &key{algorithm: MLDSA65},
		"ML-DSA-87 short":     &key{algorithm: MLDSA87, public: make([]byte, 1312)},
	}
	for name, k := range cases {
		ok, err := csp.Verify(k, []byte("sig"), mspDigest("m"), nil)
		if ok || err == nil {
			t.Fatalf("%s: got (%v, %v), want (false, error)", name, ok, err)
		}
		t.Logf("%s: %v", name, err)
	}
}
