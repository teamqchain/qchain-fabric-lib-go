/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pqc

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/signer"
)

var mldsaSets = []struct {
	name   string
	params mldsa.Parameters
}{
	{MLDSA44, mldsa.MLDSA44()},
	{MLDSA65, mldsa.MLDSA65()},
	{MLDSA87, mldsa.MLDSA87()},
}

func TestMLDSAKeyGenIsSeedBacked(t *testing.T) {
	for _, set := range mldsaSets {
		t.Run(set.name, func(t *testing.T) {
			csp, err := NewWithFileKeyStore(t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			k, err := csp.KeyGen(&KeyGenOpts{AlgorithmName: set.name, Temporary: true})
			if err != nil {
				t.Fatal(err)
			}
			v := k.(*key)
			if len(v.seed) != mldsa.PrivateKeySize || len(v.secret) != 0 {
				t.Fatalf("want a %d-byte seed and no liboqs secret, got seed=%d secret=%d bytes", mldsa.PrivateKeySize, len(v.seed), len(v.secret))
			}
			if len(v.public) != set.params.PublicKeySize() {
				t.Fatalf("public key is %d bytes, want %d", len(v.public), set.params.PublicKeySize())
			}
			// The seed must reproduce the public key.
			sk, err := mldsa.NewPrivateKey(set.params, v.seed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sk.PublicKey().Bytes(), v.public) {
				t.Fatal("seed does not derive the key's public key")
			}
			// Public Bytes() stays PKIX DER.
			pk, err := k.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			der, err := pk.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				t.Fatalf("public Bytes() is not PKIX DER: %v", err)
			}
			if mp, ok := parsed.(*mldsa.PublicKey); !ok || mp.Parameters() != set.params || !bytes.Equal(mp.Bytes(), v.public) {
				t.Fatalf("PKIX public key is %T, does not match", parsed)
			}
		})
	}
}

func TestMLDSAKeyGenSignsRepeatedly(t *testing.T) {
	for _, set := range mldsaSets {
		t.Run(set.name, func(t *testing.T) {
			csp, err := NewWithFileKeyStore(t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			k, err := csp.KeyGen(&KeyGenOpts{AlgorithmName: set.name, Temporary: true})
			if err != nil {
				t.Fatal(err)
			}
			pub, err := mldsa.NewPublicKey(set.params, k.(*key).public)
			if err != nil {
				t.Fatal(err)
			}
			for i := 1; i <= repeat; i++ {
				msg := []byte(fmt.Sprintf("message %d", i))
				sig, err := csp.Sign(k, msg, nil)
				if err != nil {
					t.Fatalf("sign #%d: %v", i, err)
				}
				if len(sig) != set.params.SignatureSize() {
					t.Fatalf("signature #%d is %d bytes, want %d", i, len(sig), set.params.SignatureSize())
				}
				if err := mldsa.Verify(pub, msg, sig, nil); err != nil {
					t.Fatalf("signature #%d does not verify with crypto/mldsa: %v", i, err)
				}
				if ok, err := csp.Verify(k, sig, msg, nil); err != nil || !ok {
					t.Fatalf("signature #%d does not verify with the BCCSP (ok=%v, err=%v)", i, ok, err)
				}
				if err := mldsa.Verify(pub, append(msg, '!'), sig, nil); err == nil {
					t.Fatalf("signature #%d verified a different message", i)
				}
			}
		})
	}
}

func TestMLDSAStdlibKeyVerifiesInBCCSP(t *testing.T) {
	for _, set := range mldsaSets {
		t.Run(set.name, func(t *testing.T) {
			csp, err := NewWithFileKeyStore(t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			sk, err := mldsa.GenerateKey(set.params)
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("signed by crypto/mldsa")
			sig, err := sk.Sign(nil, msg, nil)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := csp.KeyImport(sk.PublicKey().Bytes(), &PublicKeyImportOpts{AlgorithmName: set.name, Temporary: true})
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := csp.Verify(pub, sig, msg, nil); err != nil || !ok {
				t.Fatalf("stdlib signature does not verify in the BCCSP (ok=%v, err=%v)", ok, err)
			}
		})
	}
}

func TestMLDSASKIStableAcrossExportImport(t *testing.T) {
	for _, set := range mldsaSets {
		t.Run(set.name, func(t *testing.T) {
			dir := t.TempDir()
			csp, err := NewWithFileKeyStore(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			k, err := csp.KeyGen(&KeyGenOpts{AlgorithmName: set.name})
			if err != nil {
				t.Fatal(err)
			}
			ski := k.SKI()
			public := k.(*key).public
			seed, err := k.Bytes()
			if err != nil {
				t.Fatal(err)
			}

			// Private: re-import the exported seed.
			priv, err := csp.KeyImport(seed, &PrivateKeyImportOpts{AlgorithmName: set.name, PublicKey: public, Temporary: true})
			if err != nil {
				t.Fatal(err)
			}
			clear(seed)
			if !bytes.Equal(priv.SKI(), ski) {
				t.Fatal("SKI changed after seed export/import")
			}

			// Public: raw import and X.509 import.
			raw, err := csp.KeyImport(append([]byte(nil), public...), &PublicKeyImportOpts{AlgorithmName: set.name, Temporary: true})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw.SKI(), ski) {
				t.Fatal("SKI changed after raw public import")
			}
			cert := selfSignedCert(t, csp, k)
			fromCert, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(fromCert.SKI(), ski) {
				t.Fatal("SKI changed after X.509 import")
			}

			// Stored key: reload by SKI from a fresh CSP on the same directory.
			fresh, err := NewWithFileKeyStore(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := fresh.GetKey(ski)
			if err != nil {
				t.Fatal(err)
			}
			if !loaded.Private() || !bytes.Equal(loaded.SKI(), ski) {
				t.Fatal("reloaded key is not the same private key")
			}
			msg := []byte("after reload")
			sig, err := fresh.Sign(loaded, msg, nil)
			if err != nil {
				t.Fatal(err)
			}
			pub, _ := mldsa.NewPublicKey(set.params, public)
			if err := mldsa.Verify(pub, msg, sig, nil); err != nil {
				t.Fatalf("reloaded key signature does not verify: %v", err)
			}
		})
	}
}

// selfSignedCert issues a certificate for k through the BCCSP crypto.Signer.
func selfSignedCert(t *testing.T, csp bccsp.BCCSP, k bccsp.Key) *x509.Certificate {
	t.Helper()
	s, err := signer.New(csp, k)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ski-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, s.Public(), s)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
