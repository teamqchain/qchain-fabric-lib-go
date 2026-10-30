/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pqc

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
)

// An ML-DSA seed key keeps its expanded crypto/mldsa key, so Sign does not
// rebuild it (about 200 KB) from the seed on every call.

func signConcurrently(t *testing.T, csp bccsp.BCCSP, k bccsp.Key, pk *mldsa.PublicKey, workers, signs int) {
	t.Helper()
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < signs; i++ {
				msg := []byte(fmt.Sprintf("worker %d message %d", w, i))
				sig, err := csp.Sign(k, msg, nil)
				if err != nil {
					t.Errorf("worker %d sign #%d: %v", w, i, err)
					return
				}
				if err := mldsa.Verify(pk, msg, sig, nil); err != nil {
					t.Errorf("worker %d signature #%d does not verify with crypto/mldsa: %v", w, i, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

func TestMLDSAKeySignsConcurrently(t *testing.T) {
	csp, _ := NewWithFileKeyStore(t.TempDir(), nil)
	k, err := csp.KeyGen(&KeyGenOpts{AlgorithmName: MLDSA44, Temporary: true})
	if err != nil {
		t.Fatal(err)
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), k.(*key).public)
	if err != nil {
		t.Fatal(err)
	}
	signConcurrently(t, csp, k, pk, 64, 8)

	// A key built without an expanded key (as a legacy .pqc load does) is
	// expanded on first use; here 64 goroutines race to do that.
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	lazy := &key{algorithm: MLDSA44, private: true, seed: sk.Bytes(), public: sk.PublicKey().Bytes()}
	signConcurrently(t, csp, lazy, sk.PublicKey(), 64, 2)
}

func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestMLDSASignDoesNotReexpandKey(t *testing.T) {
	const signs, perSign = 100, 32 << 10
	dir := t.TempDir()
	csp, _ := NewWithFileKeyStore(dir, nil)
	generated, err := csp.KeyGen(&KeyGenOpts{AlgorithmName: MLDSA44})
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := NewWithFileKeyStore(dir, nil)
	loaded, err := fresh.GetKey(generated.SKI())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("message")
	for name, k := range map[string]bccsp.Key{"KeyGen": generated, "GetKey": loaded} {
		if _, err := csp.Sign(k, msg, nil); err != nil {
			t.Fatal(err)
		}
		got := allocated(func() {
			for i := 0; i < signs; i++ {
				if _, err := csp.Sign(k, msg, nil); err != nil {
					t.Fatal(err)
				}
			}
		})
		t.Logf("%s key: %d signs allocated %d bytes", name, signs, got)
		if got > signs*perSign {
			t.Fatalf("%s key: %d signs allocated %d bytes, want at most %d", name, signs, got, signs*perSign)
		}
	}
}

func TestMLDSAKeyGenExpandsOnce(t *testing.T) {
	const n = 20
	csp, _ := NewWithFileKeyStore(t.TempDir(), nil)
	stdlib := allocated(func() {
		for i := 0; i < n; i++ {
			if _, err := mldsa.GenerateKey(mldsa.MLDSA44()); err != nil {
				t.Fatal(err)
			}
		}
	})
	got := allocated(func() {
		for i := 0; i < n; i++ {
			if _, err := csp.KeyGen(&KeyGenOpts{AlgorithmName: MLDSA44, Temporary: true}); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Logf("%d KeyGens allocated %d bytes; crypto/mldsa.GenerateKey %d", n, got, stdlib)
	if got > stdlib*3/2 {
		t.Fatalf("%d KeyGens allocated %d bytes, want at most 1.5x the %d of crypto/mldsa.GenerateKey", n, got, stdlib)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The cache is never stored: every path writes the same <ski>_sk and <ski>_pk
// bytes as an independent PKCS#8 / PKIX encoding of the same seed.
func TestMLDSAStoredBytesAreSeedOnly(t *testing.T) {
	seed := make([]byte, mldsa.PrivateKeySize)
	rand.Read(seed)
	defer clear(seed)
	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(sk)
	wantSK := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	defer clear(wantSK)
	der, _ = x509.MarshalPKIXPublicKey(sk.PublicKey())
	wantPK := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	public := sk.PublicKey().Bytes()
	sum := sha256.Sum256(public)
	name := hex.EncodeToString(sum[:])

	checkKey := func(what string, csp bccsp.BCCSP, k bccsp.Key) {
		t.Helper()
		if got, _ := k.Bytes(); !bytes.Equal(got, seed) {
			t.Fatalf("%s: Bytes() is not the seed", what)
		}
		if !bytes.Equal(k.SKI(), sum[:]) {
			t.Fatalf("%s: SKI changed", what)
		}
		sig, err := csp.Sign(k, []byte("msg"), nil)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if ok, err := csp.Verify(k, sig, []byte("msg"), nil); !ok || err != nil {
			t.Fatalf("%s: Verify ok=%v err=%v", what, ok, err)
		}
		if err := mldsa.Verify(sk.PublicKey(), []byte("msg"), sig, nil); err != nil {
			t.Fatalf("%s: signature does not verify with crypto/mldsa: %v", what, err)
		}
	}
	storedSK := func(what string, store func(dir string)) string {
		t.Helper()
		dir := t.TempDir()
		store(dir)
		got := readFile(t, filepath.Join(dir, name+"_sk"))
		defer clear(got)
		if !bytes.Equal(got, wantSK) {
			t.Fatalf("%s: stored %s_sk differs from PKCS#8 of the seed", what, name)
		}
		return dir
	}

	// KeyImport of the seed (eager expansion).
	imported := storedSK("KeyImport", func(dir string) {
		csp, _ := NewWithFileKeyStore(dir, nil)
		k, err := csp.KeyImport(seed, &PrivateKeyImportOpts{AlgorithmName: MLDSA44, PublicKey: public})
		if err != nil {
			t.Fatal(err)
		}
		checkKey("KeyImport", csp, k)
	})
	// A struct-literal key (lazy expansion).
	storedSK("struct literal", func(dir string) {
		store, _ := NewFileKeyStore(dir, nil)
		k := &key{algorithm: MLDSA44, private: true, seed: append([]byte(nil), seed...), public: public}
		csp, _ := New(store)
		checkKey("struct literal", csp, k)
		if err := store.StoreKey(k); err != nil {
			t.Fatal(err)
		}
	})
	// GetKey of <ski>_sk, sign, then store again.
	storedSK("GetKey re-store", func(dir string) {
		csp, _ := NewWithFileKeyStore(imported, nil)
		k, err := csp.GetKey(sum[:])
		if err != nil {
			t.Fatal(err)
		}
		checkKey("GetKey", csp, k)
		store, _ := NewFileKeyStore(dir, nil)
		if err := store.StoreKey(k); err != nil {
			t.Fatal(err)
		}
	})
	// A scanned cryptogen-style priv_sk, sign, then store again.
	storedSK("priv_sk re-store", func(dir string) {
		ks := t.TempDir()
		writePrivSk(t, ks, sk)
		csp, _ := NewWithFileKeyStore(ks, nil)
		k, err := csp.GetKey(sum[:])
		if err != nil {
			t.Fatal(err)
		}
		checkKey("priv_sk", csp, k)
		store, _ := NewFileKeyStore(dir, nil)
		if err := store.StoreKey(k); err != nil {
			t.Fatal(err)
		}
	})

	// The public key alone.
	dir := t.TempDir()
	priv := &key{algorithm: MLDSA44, private: true, seed: append([]byte(nil), seed...), public: public}
	pub, _ := priv.PublicKey()
	store, _ := NewFileKeyStore(dir, nil)
	if err := store.StoreKey(pub); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, name+"_pk")); !bytes.Equal(got, wantPK) {
		t.Fatalf("stored %s_pk differs from PKIX of the public key", name)
	}
}
