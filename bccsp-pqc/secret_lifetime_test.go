/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pqc

import (
	"bytes"
	"crypto/mldsa"
	"fmt"
	"testing"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// liboqs's Init keeps the secret-key slice it is given and Clean wipes it.
// These tests use one key object many times, so a wiped key.secret shows up
// as a signature or shared secret that stops matching after the first use.

const repeat = 25

func TestSignRepeatedlyWithOneKey(t *testing.T) {
	csp, err := NewWithFileKeyStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := csp.KeyGen(&KeyGenOpts{AlgorithmName: MLDSA44, Temporary: true})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA44(), k.(*key).public)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= repeat; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		sig, err := csp.Sign(k, msg, nil)
		if err != nil {
			t.Fatalf("sign #%d: %v", i, err)
		}
		if ok, err := csp.Verify(k, sig, msg, nil); err != nil || !ok {
			t.Fatalf("signature #%d does not verify with liboqs (ok=%v, err=%v)", i, ok, err)
		}
		if err := mldsa.Verify(pub, msg, sig, nil); err != nil {
			t.Fatalf("signature #%d does not verify with crypto/mldsa: %v", i, err)
		}
	}
}

func TestImportedLiboqsSecretSignsRepeatedly(t *testing.T) {
	gen := oqs.Signature{}
	if err := gen.Init(MLDSA44, nil); err != nil {
		t.Fatal(err)
	}
	public, err := gen.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	secret := append([]byte(nil), gen.ExportSecretKey()...)
	gen.Clean()
	original := append([]byte(nil), secret...)

	csp, err := NewWithFileKeyStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Import runs validatePrivateKey, which also hands the secret to liboqs.
	k, err := csp.KeyImport(secret, &PrivateKeyImportOpts{AlgorithmName: MLDSA44, PublicKey: public, Temporary: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, original) {
		t.Fatal("KeyImport modified the caller's secret-key buffer")
	}
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA44(), public)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= repeat; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		sig, err := csp.Sign(k, msg, nil)
		if err != nil {
			t.Fatalf("sign #%d: %v", i, err)
		}
		if err := mldsa.Verify(pub, msg, sig, nil); err != nil {
			t.Fatalf("signature #%d from imported key does not verify: %v", i, err)
		}
	}
}

func TestDecapsulateRepeatedly(t *testing.T) {
	csp, err := NewWithFileKeyStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := csp.KeyGen(&KeyGenOpts{AlgorithmName: MLKEM768, Temporary: true})
	if err != nil {
		t.Fatal(err)
	}
	gk := generated.(*key)
	// The same key material imported, which also runs validatePrivateKey.
	imported, err := csp.KeyImport(append([]byte(nil), gk.secret...), &PrivateKeyImportOpts{AlgorithmName: MLKEM768, PublicKey: gk.public, Temporary: true})
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]*key{"generated": gk, "imported": imported.(*key)} {
		ciphertext, want, err := csp.Encapsulate(k)
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= repeat; i++ {
			got, err := csp.Decapsulate(k, ciphertext)
			if err != nil {
				t.Fatalf("%s key: decapsulate #%d: %v", name, i, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s key: decapsulate #%d returned a different shared secret", name, i)
			}
		}
	}
}
