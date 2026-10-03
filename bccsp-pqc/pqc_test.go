/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pqc

import (
	"bytes"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
)

func TestFileKeyStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileKeyStore(dir, []byte("test-password"))
	if err != nil {
		t.Fatal(err)
	}
	want := &key{
		algorithm: MLDSA44,
		private:   true,
		secret:    []byte("private-key-material"),
		public:    []byte("public-key-material"),
	}
	if err := store.StoreKey(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetKey(want.SKI())
	if err != nil {
		t.Fatal(err)
	}
	value, ok := got.(*key)
	if !ok {
		t.Fatalf("unexpected key type %T", got)
	}
	if value.algorithm != want.algorithm || value.private != want.private || !bytes.Equal(value.secret, want.secret) || !bytes.Equal(value.public, want.public) {
		t.Fatalf("round trip changed key material")
	}
}

func TestKeyMetadata(t *testing.T) {
	value := &key{algorithm: MLKEM768, public: []byte("public")}
	if value.Symmetric() || value.Private() {
		t.Fatal("PQC public keys must be asymmetric and non-private")
	}
	if got, err := Algorithm(value); err != nil || got != MLKEM768 {
		t.Fatalf("unexpected algorithm metadata: %q, %v", got, err)
	}
	public, err := PublicKeyBytes(value)
	if err != nil || !bytes.Equal(public, value.public) {
		t.Fatalf("unexpected public key bytes: %x, %v", public, err)
	}
}

func TestMLDSA44SignVerifyRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	csp, err := NewWithFileKeyStore(tmpDir, nil)
	if err != nil {
		t.Fatalf("failed to create CSP: %v", err)
	}

	k, err := csp.KeyGen(&KeyGenOpts{AlgorithmName: MLDSA44})
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	digest, err := csp.Hash([]byte("this is a test message"), &bccsp.SHA256Opts{})
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	sig, err := csp.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	valid, err := csp.Verify(k, sig, digest, nil)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !valid {
		t.Fatal("signature did not verify — should have")
	}

	tamperedDigest, _ := csp.Hash([]byte("a different message"), nil)
	valid, err = csp.Verify(k, sig, tamperedDigest, nil)
	if err == nil && valid {
		t.Fatal("signature verified against a tampered digest — should have failed")
	}
}