/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pqc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
)

func TestMLDSAPublicKeyImportPKIX(t *testing.T) {
	for i, set := range mldsaSets {
		t.Run(set.name, func(t *testing.T) {
			csp, err := NewWithFileKeyStore(t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			priv, err := csp.KeyGen(&KeyGenOpts{AlgorithmName: set.name, Temporary: true})
			if err != nil {
				t.Fatal(err)
			}
			raw := priv.(*key).public
			pub, _ := priv.PublicKey()
			der, err := pub.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			opts := &PublicKeyImportOpts{AlgorithmName: set.name, Temporary: true}

			fromRaw, err := csp.KeyImport(append([]byte(nil), raw...), opts)
			if err != nil {
				t.Fatalf("raw import: %v", err)
			}
			fromPKIX, err := csp.KeyImport(der, opts)
			if err != nil {
				t.Fatalf("PKIX import: %v", err)
			}
			if !bytes.Equal(fromRaw.SKI(), fromPKIX.SKI()) || !bytes.Equal(fromPKIX.SKI(), priv.SKI()) {
				t.Fatal("raw and PKIX imports of the same key have different SKIs")
			}
			if !bytes.Equal(fromPKIX.(*key).public, raw) {
				t.Fatal("PKIX import does not hold the raw public key")
			}

			msg := []byte("verify with an imported public key")
			sig, err := csp.Sign(priv, msg, nil)
			if err != nil {
				t.Fatal(err)
			}
			for name, k := range map[string]interface{ SKI() []byte }{"raw": fromRaw, "PKIX": fromPKIX} {
				if ok, err := csp.Verify(k.(*key), sig, msg, nil); err != nil || !ok {
					t.Fatalf("%s-imported key does not verify (ok=%v, err=%v)", name, ok, err)
				}
			}

			// Non-ephemeral PKIX import is stored as <ski>_pk and reloads.
			stored, err := csp.KeyImport(der, &PublicKeyImportOpts{AlgorithmName: set.name})
			if err != nil {
				t.Fatal(err)
			}
			if got, err := csp.GetKey(stored.SKI()); err != nil || got.Private() || !bytes.Equal(got.SKI(), priv.SKI()) {
				t.Fatalf("stored PKIX import does not reload (err=%v)", err)
			}

			ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			ecDER, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
			other := mldsaSets[(i+1)%len(mldsaSets)]
			otherKey, _ := mldsa.GenerateKey(other.params)
			otherDER, _ := x509.MarshalPKIXPublicKey(otherKey.PublicKey())

			for _, c := range []struct {
				name  string
				input []byte
				want  string
			}{
				{"garbage", []byte("not a public key"), "neither"},
				{"raw minus one byte", raw[:len(raw)-1], "neither"},
				{"raw plus one byte", append(append([]byte(nil), raw...), 0), "neither"},
				{"ECDSA PKIX", ecDER, "not an ML-DSA key"},
				{other.name + " PKIX", otherDER, "not " + set.name},
			} {
				_, err := csp.KeyImport(c.input, opts)
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("%s: err=%v, want it to mention %q", c.name, err, c.want)
				}
				t.Logf("%s: %v", c.name, err)
			}
		})
	}
}
