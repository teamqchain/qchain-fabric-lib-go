/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pqc

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func pemType(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s is not PEM", filepath.Base(path))
	}
	return block.Type
}

func signAndVerify(t *testing.T, csp bccsp.BCCSP, k bccsp.Key, pub []byte, params mldsa.Parameters) {
	t.Helper()
	pk, err := mldsa.NewPublicKey(params, pub)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		msg := []byte{byte(i), 'm', 's', 'g'}
		sig, err := csp.Sign(k, msg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := mldsa.Verify(pk, msg, sig, nil); err != nil {
			t.Fatalf("signature #%d does not verify: %v", i+1, err)
		}
	}
}

// writeLegacy writes k in the pre-PKCS#8 <ski>.pqc JSON format.
func writeLegacy(t *testing.T, store *FileKeyStore, k *key) {
	t.Helper()
	data, err := json.Marshal(storedKey{Algorithm: k.algorithm, Private: k.private, Secret: encode(k.secret), Public: encode(k.public), Seed: encode(k.seed)})
	if err != nil {
		t.Fatal(err)
	}
	data, err = store.protect(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.path, hex.EncodeToString(k.SKI())+".pqc"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestKeystoreMLDSAPrivateKeyIsPKCS8SK(t *testing.T) {
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
			want := hex.EncodeToString(k.SKI()) + "_sk"
			if got := dirNames(t, dir); len(got) != 1 || got[0] != want {
				t.Fatalf("keystore holds %v, want only [%s]", got, want)
			}
			// fabric-ca-client's MySkFile and mkwallet look for *_sk.
			if m, _ := filepath.Glob(filepath.Join(dir, "*_sk")); len(m) != 1 {
				t.Fatalf("*_sk glob matched %d files", len(m))
			}
			path := filepath.Join(dir, want)
			if typ := pemType(t, path); typ != "PRIVATE KEY" {
				t.Fatalf("PEM type %q, want PRIVATE KEY", typ)
			}
			if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
				t.Fatalf("mode %v, want 0600", info.Mode().Perm())
			}
			data, _ := os.ReadFile(path)
			block, _ := pem.Decode(data)
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatalf("not PKCS#8: %v", err)
			}
			if sk, ok := parsed.(*mldsa.PrivateKey); !ok || !bytes.Equal(sk.PublicKey().Bytes(), k.(*key).public) {
				t.Fatalf("PKCS#8 holds %T, not this ML-DSA key", parsed)
			}

			// Reload by SKI from a fresh CSP, as a new process would.
			fresh, err := NewWithFileKeyStore(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := fresh.GetKey(k.SKI())
			if err != nil {
				t.Fatal(err)
			}
			if !loaded.Private() || !bytes.Equal(loaded.SKI(), k.SKI()) {
				t.Fatal("reloaded key is not the stored private key")
			}
			signAndVerify(t, fresh, loaded, k.(*key).public, set.params)
		})
	}
}

func TestKeystoreMLDSAPublicKeyIsPKIXPK(t *testing.T) {
	for _, set := range mldsaSets {
		t.Run(set.name, func(t *testing.T) {
			src, _ := NewWithFileKeyStore(t.TempDir(), nil)
			priv, err := src.KeyGen(&KeyGenOpts{AlgorithmName: set.name, Temporary: true})
			if err != nil {
				t.Fatal(err)
			}
			public := priv.(*key).public

			for name, raw := range map[string]interface{}{"raw": append([]byte(nil), public...), "x509": selfSignedCert(t, src, priv)} {
				dir := t.TempDir()
				csp, _ := NewWithFileKeyStore(dir, nil)
				var opts bccsp.KeyImportOpts = &PublicKeyImportOpts{AlgorithmName: set.name}
				if name == "x509" {
					opts = &bccsp.X509PublicKeyImportOpts{}
				}
				if _, err := csp.KeyImport(raw, opts); err != nil {
					t.Fatalf("%s import: %v", name, err)
				}
				want := hex.EncodeToString(priv.SKI()) + "_pk"
				if got := dirNames(t, dir); len(got) != 1 || got[0] != want {
					t.Fatalf("%s: keystore holds %v, want only [%s]", name, got, want)
				}
				if typ := pemType(t, filepath.Join(dir, want)); typ != "PUBLIC KEY" {
					t.Fatalf("%s: PEM type %q, want PUBLIC KEY", name, typ)
				}
				fresh, _ := NewWithFileKeyStore(dir, nil)
				loaded, err := fresh.GetKey(priv.SKI())
				if err != nil {
					t.Fatalf("%s: GetKey: %v", name, err)
				}
				if loaded.Private() || !bytes.Equal(loaded.SKI(), priv.SKI()) {
					t.Fatalf("%s: reloaded key is not the stored public key", name)
				}
				msg := []byte("verify with stored public key")
				sig, _ := src.Sign(priv, msg, nil)
				if ok, err := fresh.Verify(loaded, sig, msg, nil); err != nil || !ok {
					t.Fatalf("%s: stored public key does not verify (ok=%v, err=%v)", name, ok, err)
				}
			}
		})
	}
}

func TestKeystoreLegacyPQCStillLoads(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	seedKey, _ := newSeedKey(MLDSA44, sk.Bytes())

	gen := oqs.Signature{}
	if err := gen.Init(MLDSA44, nil); err != nil {
		t.Fatal(err)
	}
	public, _ := gen.GenerateKeyPair()
	liboqsKey := &key{algorithm: MLDSA44, private: true, secret: append([]byte(nil), gen.ExportSecretKey()...), public: public}
	gen.Clean()

	for _, password := range [][]byte{nil, []byte("legacy-password")} {
		for name, k := range map[string]*key{"seed": seedKey, "liboqs-secret": liboqsKey} {
			store, err := NewFileKeyStore(t.TempDir(), password)
			if err != nil {
				t.Fatal(err)
			}
			writeLegacy(t, store, k)
			before := dirNames(t, store.path)
			csp, _ := New(store)
			loaded, err := csp.GetKey(k.SKI())
			if err != nil {
				t.Fatalf("%s (password=%v): legacy .pqc does not load: %v", name, password != nil, err)
			}
			signAndVerify(t, csp, loaded, k.public, mldsa.MLDSA44())
			if after := dirNames(t, store.path); strings.Join(after, ",") != strings.Join(before, ",") {
				t.Fatalf("%s: reading a legacy key changed the keystore: %v -> %v", name, before, after)
			}
		}
	}
}

func TestKeystoreMLKEMKeepsPQCFormat(t *testing.T) {
	for _, password := range [][]byte{nil, []byte("kem-password")} {
		dir := t.TempDir()
		csp, err := NewWithFileKeyStore(dir, password)
		if err != nil {
			t.Fatal(err)
		}
		k, err := csp.KeyGen(&KeyGenOpts{AlgorithmName: MLKEM768})
		if err != nil {
			t.Fatal(err)
		}
		want := hex.EncodeToString(k.SKI()) + ".pqc"
		if got := dirNames(t, dir); len(got) != 1 || got[0] != want {
			t.Fatalf("keystore holds %v, want only [%s]", got, want)
		}
		data, _ := os.ReadFile(filepath.Join(dir, want))
		if encrypted := !json.Valid(data); encrypted != (password != nil) {
			t.Fatalf("password=%v but file encrypted=%v", password != nil, encrypted)
		}
		fresh, _ := NewWithFileKeyStore(dir, password)
		loaded, err := fresh.GetKey(k.SKI())
		if err != nil {
			t.Fatal(err)
		}
		ct, ss, err := fresh.Encapsulate(loaded)
		if err != nil {
			t.Fatal(err)
		}
		got, err := fresh.Decapsulate(loaded, ct)
		if err != nil || !bytes.Equal(got, ss) {
			t.Fatalf("reloaded ML-KEM key does not decapsulate (err=%v)", err)
		}
	}
}

func TestKeystorePasswordRejectsMLDSA(t *testing.T) {
	dir := t.TempDir()
	csp, err := NewWithFileKeyStore(dir, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = csp.KeyGen(&KeyGenOpts{AlgorithmName: MLDSA44})
	if err == nil || !strings.Contains(err.Error(), "password is not supported") {
		t.Fatalf("storing an ML-DSA private key with a password: err=%v", err)
	}
	t.Logf("private: %v", err)
	eph, err := csp.KeyGen(&KeyGenOpts{AlgorithmName: MLDSA44, Temporary: true})
	if err != nil {
		t.Fatalf("ephemeral ML-DSA keys must still work with a password: %v", err)
	}
	if got := dirNames(t, dir); len(got) != 0 {
		t.Fatalf("failed store left files: %v", got)
	}

	// Public keys are not secret: stored unencrypted as <ski>_pk despite the password.
	if _, err := csp.KeyImport(eph.(*key).public, &PublicKeyImportOpts{AlgorithmName: MLDSA44}); err != nil {
		t.Fatalf("storing an ML-DSA public key with a password: %v", err)
	}
	want := hex.EncodeToString(eph.SKI()) + "_pk"
	if got := dirNames(t, dir); len(got) != 1 || got[0] != want {
		t.Fatalf("keystore holds %v, want only [%s]", got, want)
	}
	if typ := pemType(t, filepath.Join(dir, want)); typ != "PUBLIC KEY" {
		t.Fatalf("PEM type %q, want unencrypted PUBLIC KEY", typ)
	}
	fresh, _ := NewWithFileKeyStore(dir, []byte("secret"))
	if got, err := fresh.GetKey(eph.SKI()); err != nil || got.Private() {
		t.Fatalf("stored public key does not reload (err=%v)", err)
	}
}

func TestKeystoreRejectsSeedlessMLDSAImport(t *testing.T) {
	gen := oqs.Signature{}
	if err := gen.Init(MLDSA44, nil); err != nil {
		t.Fatal(err)
	}
	public, _ := gen.GenerateKeyPair()
	secret := append([]byte(nil), gen.ExportSecretKey()...)
	gen.Clean()
	defer clear(secret)

	dir := t.TempDir()
	csp, _ := NewWithFileKeyStore(dir, nil)
	_, err := csp.KeyImport(secret, &PrivateKeyImportOpts{AlgorithmName: MLDSA44, PublicKey: public})
	if err == nil || !strings.Contains(err.Error(), "without its seed") {
		t.Fatalf("non-ephemeral seedless import: err=%v", err)
	}
	t.Logf("non-ephemeral: %v", err)
	if got := dirNames(t, dir); len(got) != 0 {
		t.Fatalf("failed import left files: %v", got)
	}
	if _, err := csp.KeyImport(secret, &PrivateKeyImportOpts{AlgorithmName: MLDSA44, PublicKey: public, Temporary: true}); err != nil {
		t.Fatalf("ephemeral seedless import must stay memory-only and succeed: %v", err)
	}
}

func TestKeystoreScanIgnoresPublicKeyPEMs(t *testing.T) {
	dir := t.TempDir()
	src, _ := NewWithFileKeyStore(t.TempDir(), nil)
	k, _ := src.KeyGen(&KeyGenOpts{AlgorithmName: MLDSA44, Temporary: true})
	pub, _ := k.PublicKey()
	pkix, _ := pub.Bytes()
	// A public key under an arbitrary name: the scan must not return it.
	os.WriteFile(filepath.Join(dir, "cert_pub.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}), 0o600)
	csp, _ := NewWithFileKeyStore(dir, nil)
	if got, err := csp.GetKey(k.SKI()); err == nil {
		t.Fatalf("scan returned a key (private=%v) from a PUBLIC KEY PEM", got.Private())
	}
	// The matching private key under an arbitrary name: found.
	seed, _ := k.Bytes()
	sk, _ := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	clear(seed)
	der, _ := x509.MarshalPKCS8PrivateKey(sk)
	os.WriteFile(filepath.Join(dir, "priv_sk"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	clear(der)
	got, err := csp.GetKey(k.SKI())
	if err != nil || !got.Private() {
		t.Fatalf("scan did not find the private key (err=%v)", err)
	}
}

func TestKeystoreLookupOrder(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	priv, _ := newSeedKey(MLDSA44, sk.Bytes())
	pub := &key{algorithm: MLDSA44, public: priv.public}

	// _sk before legacy .pqc.
	store, _ := NewFileKeyStore(t.TempDir(), nil)
	writeLegacy(t, store, pub)
	if err := store.StoreKey(priv); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetKey(priv.SKI()); err != nil || !got.Private() {
		t.Fatalf("_sk must win over .pqc (err=%v)", err)
	}

	// _pk before legacy .pqc: with an unreadable .pqc next to it, GetKey
	// still returns the _pk key, so .pqc is never consulted.
	store, _ = NewFileKeyStore(t.TempDir(), nil)
	if err := store.StoreKey(pub); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(store.path, hex.EncodeToString(priv.SKI())+".pqc"), []byte("not json"), 0o600)
	if got, err := store.GetKey(priv.SKI()); err != nil || got.Private() {
		t.Fatalf("_pk must win over .pqc (err=%v)", err)
	}

	// Legacy .pqc before the directory scan.
	store, _ = NewFileKeyStore(t.TempDir(), nil)
	writeLegacy(t, store, pub)
	der, _ := x509.MarshalPKCS8PrivateKey(sk)
	os.WriteFile(filepath.Join(store.path, "priv_sk"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	clear(der)
	if got, err := store.GetKey(priv.SKI()); err != nil || got.Private() {
		t.Fatalf(".pqc must win over the scan (err=%v)", err)
	}

	// A <ski>_sk holding a different key is an error, not a silent mismatch.
	store, _ = NewFileKeyStore(t.TempDir(), nil)
	other, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	der, _ = x509.MarshalPKCS8PrivateKey(other)
	os.WriteFile(filepath.Join(store.path, hex.EncodeToString(priv.SKI())+"_sk"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	clear(der)
	if _, err := store.GetKey(priv.SKI()); err == nil || !strings.Contains(err.Error(), "different SKI") {
		t.Fatalf("mismatched _sk: err=%v", err)
	}
}

// A non-ephemeral certificate import must not write a <ski>_pk that would
// hide the private key already in the keystore.
func TestKeystoreCertImportKeepsPrivateKey(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	priv, _ := newSeedKey(MLDSA44, sk.Bytes())
	for _, held := range []string{"legacy .pqc", "_sk"} {
		dir := t.TempDir()
		store, _ := NewFileKeyStore(dir, nil)
		if held == "legacy .pqc" {
			writeLegacy(t, store, priv)
		} else if err := store.StoreKey(priv); err != nil {
			t.Fatal(err)
		}
		before := dirNames(t, dir)
		csp, _ := New(store)
		if _, err := csp.KeyImport(selfSignedCert(t, csp, priv), &bccsp.X509PublicKeyImportOpts{}); err != nil {
			t.Fatalf("%s: cert import: %v", held, err)
		}
		if after := dirNames(t, dir); strings.Join(after, ",") != strings.Join(before, ",") {
			t.Fatalf("%s: cert import wrote %v next to %v", held, after, before)
		}
		fresh, _ := NewWithFileKeyStore(dir, nil)
		k, err := fresh.GetKey(priv.SKI())
		if err != nil || !k.Private() {
			t.Fatalf("%s: private key no longer found after cert import (err=%v)", held, err)
		}
		signAndVerify(t, fresh, k, priv.public, mldsa.MLDSA44())
	}
}

func writePrivSk(t *testing.T, dir string, sk *mldsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	if err := os.WriteFile(filepath.Join(dir, "priv_sk"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A cert import must not write <ski>_pk next to a cryptogen-style priv_sk
// for the same key: GetKey reads _pk before it scans for priv_sk.
func TestKeystoreCertImportKeepsScannedPrivSk(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	priv, _ := newSeedKey(MLDSA44, sk.Bytes())
	dir := t.TempDir()
	writePrivSk(t, dir, sk)

	csp, _ := NewWithFileKeyStore(dir, nil)
	if _, err := csp.KeyImport(selfSignedCert(t, csp, priv), &bccsp.X509PublicKeyImportOpts{}); err != nil {
		t.Fatalf("cert import: %v", err)
	}
	if got := dirNames(t, dir); len(got) != 1 || got[0] != "priv_sk" {
		t.Fatalf("cert import wrote next to priv_sk: %v", got)
	}
	fresh, _ := NewWithFileKeyStore(dir, nil)
	k, err := fresh.GetKey(priv.SKI())
	if err != nil || !k.Private() {
		t.Fatalf("priv_sk no longer found by SKI after cert import (err=%v)", err)
	}
	signAndVerify(t, fresh, k, priv.public, mldsa.MLDSA44())
}

// Without a matching private key the public key is still written, even if
// the keystore holds a priv_sk for a different key.
func TestKeystoreCertImportWritesPKWithoutPrivateKey(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	priv, _ := newSeedKey(MLDSA44, sk.Bytes())
	unrelated, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	for name, setup := range map[string]func(string){
		"empty keystore":    func(string) {},
		"unrelated priv_sk": func(dir string) { writePrivSk(t, dir, unrelated) },
	} {
		dir := t.TempDir()
		setup(dir)
		csp, _ := NewWithFileKeyStore(dir, nil)
		if _, err := csp.KeyImport(selfSignedCert(t, csp, priv), &bccsp.X509PublicKeyImportOpts{}); err != nil {
			t.Fatalf("%s: cert import: %v", name, err)
		}
		pk := filepath.Join(dir, hex.EncodeToString(priv.SKI())+"_pk")
		if typ := pemType(t, pk); typ != "PUBLIC KEY" {
			t.Fatalf("%s: %s holds %q", name, filepath.Base(pk), typ)
		}
		got, err := csp.GetKey(priv.SKI())
		if err != nil || got.Private() {
			t.Fatalf("%s: stored public key does not reload (err=%v)", name, err)
		}
	}
}

// TestKeystoreFindsCryptogenPrivSk runs cryptogen into a temp dir, copies
// each MSP keystore (keeping cryptogen's priv_sk file name) and loads the
// signing key by the certificate's SKI. Set PQC_CRYPTOGEN to a cryptogen
// binary with ML-DSA support, or put one on PATH.
func TestKeystoreFindsCryptogenPrivSk(t *testing.T) {
	bin := os.Getenv("PQC_CRYPTOGEN")
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("cryptogen"); err != nil {
			t.Skip("no cryptogen: set PQC_CRYPTOGEN to an ML-DSA capable cryptogen binary")
		}
	}
	work := t.TempDir()
	config := filepath.Join(work, "crypto-config.yaml")
	os.WriteFile(config, []byte(`PeerOrgs:
  - Name: Org1
    Domain: org1.example.com
    EnableNodeOUs: true
    CA:
      PublicKeyAlgorithm: mldsa44
    Template:
      Count: 1
      PublicKeyAlgorithm: mldsa44
    Users:
      Count: 1
      PublicKeyAlgorithm: mldsa44
`), 0o600)
	out := filepath.Join(work, "out")
	if b, err := exec.Command(bin, "generate", "--config="+config, "--output="+out).CombinedOutput(); err != nil {
		t.Fatalf("cryptogen: %v\n%s", err, b)
	}

	msps, _ := filepath.Glob(filepath.Join(out, "peerOrganizations", "*", "*", "*", "msp"))
	if len(msps) == 0 {
		t.Fatal("cryptogen produced no MSPs")
	}
	for _, msp := range msps {
		id := filepath.Base(filepath.Dir(msp))
		keys, _ := filepath.Glob(filepath.Join(msp, "keystore", "*"))
		certs, _ := filepath.Glob(filepath.Join(msp, "signcerts", "*.pem"))
		if len(keys) != 1 || filepath.Base(keys[0]) != "priv_sk" || len(certs) != 1 {
			t.Fatalf("%s: unexpected keystore %v / signcerts %v", id, keys, certs)
		}
		ks := filepath.Join(t.TempDir(), "keystore")
		os.MkdirAll(ks, 0o700)
		data, _ := os.ReadFile(keys[0])
		os.WriteFile(filepath.Join(ks, "priv_sk"), data, 0o600)
		clear(data)

		certPEM, _ := os.ReadFile(certs[0])
		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		csp, _ := NewWithFileKeyStore(ks, nil)
		pub, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		k, err := csp.GetKey(pub.SKI())
		if err != nil || !k.Private() {
			t.Fatalf("%s: priv_sk not found by SKI (err=%v)", id, err)
		}
		signAndVerify(t, csp, k, cert.PublicKey.(*mldsa.PublicKey).Bytes(), mldsa.MLDSA44())
		if got := dirNames(t, ks); len(got) != 1 || got[0] != "priv_sk" {
			t.Fatalf("%s: loading wrote to the keystore: %v", id, got)
		}
		t.Logf("%s: priv_sk found by SKI and signs", id)
	}
}
