/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pqc

import (
	"crypto/mldsa"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
)

func TestValidateMLDSAPublicKey(t *testing.T) {
	for i, set := range mldsaSets {
		t.Run(set.name, func(t *testing.T) {
			sk, err := mldsa.GenerateKey(set.params)
			if err != nil {
				t.Fatal(err)
			}
			valid := sk.PublicKey().Bytes()
			other := mldsaSets[(i+1)%len(mldsaSets)]
			otherKey, _ := mldsa.GenerateKey(other.params)

			if err := validatePublicKey(&key{algorithm: set.name, public: valid}); err != nil {
				t.Fatalf("valid key rejected: %v", err)
			}
			for name, public := range map[string][]byte{
				"empty":             nil,
				"short":             valid[:len(valid)-1],
				"long":              append(append([]byte(nil), valid...), 0),
				other.name + " key": otherKey.PublicKey().Bytes(),
				"three bytes":       {1, 2, 3},
			} {
				err := validatePublicKey(&key{algorithm: set.name, public: public})
				if err == nil {
					t.Fatalf("%s: accepted", name)
				}
				t.Logf("%s: %v", name, err)
			}

			// Valid keys still import through the public API.
			csp, _ := NewWithFileKeyStore(t.TempDir(), nil)
			if _, err := csp.KeyImport(valid, &PublicKeyImportOpts{AlgorithmName: set.name, Temporary: true}); err != nil {
				t.Fatalf("raw import: %v", err)
			}
			priv, _ := newSeedKey(set.name, sk.Bytes())
			if _, err := csp.KeyImport(selfSignedCert(t, csp, priv), &bccsp.X509PublicKeyImportOpts{Temporary: true}); err != nil {
				t.Fatalf("X.509 import: %v", err)
			}
		})
	}
}
