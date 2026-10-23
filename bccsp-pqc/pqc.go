/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package pqc provides a BCCSP implementation backed by liboqs-go.
//
// The signature implementation supports the standardized ML-DSA-44,
// ML-DSA-65, and ML-DSA-87 algorithms. The KEM implementation supports the
// standardized ML-KEM-512, ML-KEM-768, and ML-KEM-1024 algorithms.
package pqc

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

const (
	MLDSA44   = "ML-DSA-44"
	MLDSA65   = "ML-DSA-65"
	MLDSA87   = "ML-DSA-87"
	MLKEM512  = "ML-KEM-512"
	MLKEM768  = "ML-KEM-768"
	MLKEM1024 = "ML-KEM-1024"
)

var signatureAlgorithms = map[string]bool{MLDSA44: true, MLDSA65: true, MLDSA87: true}
var kemAlgorithms = map[string]bool{MLKEM512: true, MLKEM768: true, MLKEM1024: true}

type KeyGenOpts struct {
	AlgorithmName string
	Temporary     bool
}

func (o *KeyGenOpts) Algorithm() string { return o.AlgorithmName }
func (o *KeyGenOpts) Ephemeral() bool   { return o.Temporary }

type PrivateKeyImportOpts struct {
	AlgorithmName string
	Temporary     bool
	PublicKey     []byte
}

func (o *PrivateKeyImportOpts) Algorithm() string { return o.AlgorithmName }
func (o *PrivateKeyImportOpts) Ephemeral() bool   { return o.Temporary }

type PublicKeyImportOpts struct {
	AlgorithmName string
	Temporary     bool
}

func (o *PublicKeyImportOpts) Algorithm() string { return o.AlgorithmName }
func (o *PublicKeyImportOpts) Ephemeral() bool   { return o.Temporary }

type key struct {
	algorithm string
	private   bool
	secret    []byte
	public    []byte
	// seed is set for ML-DSA keys imported from a crypto/mldsa (FIPS 204)
	// 32-byte seed. Such keys sign via crypto/mldsa; secret is unused.
	seed []byte
}

// newSeedKey builds an ML-DSA private key from a crypto/mldsa seed. The
// public key is derived from the seed, so SKI matches the liboqs form.
func newSeedKey(algorithm string, seed []byte) (*key, error) {
	params, err := mldsaParameters(algorithm)
	if err != nil {
		return nil, err
	}
	sk, err := mldsa.NewPrivateKey(params, seed)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-DSA seed: %w", err)
	}
	return &key{algorithm: algorithm, private: true, seed: append([]byte(nil), seed...), public: sk.PublicKey().Bytes()}, nil
}

// mldsaAlgorithm maps a raw ML-DSA public key to its algorithm name.
func mldsaAlgorithm(rawPub []byte) (string, error) {
	switch len(rawPub) { // FIPS 204 fixed sizes — swap for a proper accessor if crypto/mldsa exposes one
	case 1312:
		return MLDSA44, nil
	case 1952:
		return MLDSA65, nil
	case 2592:
		return MLDSA87, nil
	default:
		return "", fmt.Errorf("unrecognized ML-DSA public key length: %d", len(rawPub))
	}
}

func mldsaParameters(algorithm string) (mldsa.Parameters, error) {
	switch algorithm {
	case MLDSA44:
		return mldsa.MLDSA44(), nil
	case MLDSA65:
		return mldsa.MLDSA65(), nil
	case MLDSA87:
		return mldsa.MLDSA87(), nil
	default:
		return mldsa.Parameters{}, fmt.Errorf("not an ML-DSA algorithm: %q", algorithm)
	}
}

/* func (k *key) Bytes() ([]byte, error) {
	if !k.private {
		return append([]byte(nil), k.public...), nil
	}
	return append([]byte(nil), k.secret...), nil
} */

func (k *key) Bytes() ([]byte, error) {
	if !k.private {
		if signatureAlgorithms[k.algorithm] {
			params, err := mldsaParameters(k.algorithm)
			if err != nil {
				return nil, err
			}
			pub, err := mldsa.NewPublicKey(params, k.public)
			if err != nil {
				return nil, fmt.Errorf("reconstruct ML-DSA public key: %w", err)
			}
			return x509.MarshalPKIXPublicKey(pub)
		}
		// ML-KEM public keys have no PKIX/x509 identity role — keep raw.
		return append([]byte(nil), k.public...), nil
	}
	if len(k.seed) > 0 {
		return append([]byte(nil), k.seed...), nil
	}
	return append([]byte(nil), k.secret...), nil
}

func (k *key) SKI() []byte {
	sum := sha256.Sum256(k.public)
	return append([]byte(nil), sum[:]...)
}

func (k *key) Symmetric() bool { return false }
func (k *key) Private() bool   { return k.private }

func (k *key) PublicKey() (bccsp.Key, error) {
	if !k.private {
		return nil, errors.New("public key has no public-key projection")
	}
	return &key{algorithm: k.algorithm, public: append([]byte(nil), k.public...)}, nil
}

// KEM is the explicit KEM extension to BCCSP. KEMs do not fit Encrypt and
// Decrypt because encapsulation returns both ciphertext and a shared secret.
type KEM interface {
	Encapsulate(k bccsp.Key) (ciphertext, sharedSecret []byte, err error)
	Decapsulate(k bccsp.Key, ciphertext []byte) (sharedSecret []byte, err error)
}

type CSP struct {
	store bccsp.KeyStore
}

var _ bccsp.BCCSP = (*CSP)(nil)
var _ KEM = (*CSP)(nil)

func New(store bccsp.KeyStore) (*CSP, error) {
	if store == nil {
		return nil, errors.New("key store must not be nil")
	}
	return &CSP{store: store}, nil
}

// NewWithFileKeyStore creates a PQC BCCSP backed by an encrypted filesystem
// keystore when password is non-empty.
func NewWithFileKeyStore(path string, password []byte) (*CSP, error) {
	store, err := NewFileKeyStore(path, password)
	if err != nil {
		return nil, err
	}
	return New(store)
}

func (c *CSP) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	if opts == nil || opts.Algorithm() == "" {
		return nil, errors.New("PQC key generation options are required")
	}
	algorithm := opts.Algorithm()
	var generated bccsp.Key
	var err error
	switch {
	case signatureAlgorithms[algorithm]:
		generated, err = generateSignatureKey(algorithm)
	case kemAlgorithms[algorithm]:
		generated, err = generateKEMKey(algorithm)
	default:
		return nil, fmt.Errorf("unsupported PQC key-generation algorithm %q", algorithm)
	}
	if err != nil {
		return nil, err
	}
	if !opts.Ephemeral() {
		if err := c.store.StoreKey(generated); err != nil {
			return nil, fmt.Errorf("store %s key: %w", algorithm, err)
		}
	}
	return generated, nil
}

// generateSignatureKey creates an ML-DSA key with crypto/mldsa. The key is
// held as its FIPS 204 seed, the same form cryptogen writes as PKCS#8.
func generateSignatureKey(algorithm string) (bccsp.Key, error) {
	params, err := mldsaParameters(algorithm)
	if err != nil {
		return nil, err
	}
	sk, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, err
	}
	seed := sk.Bytes()
	defer clear(seed)
	return newSeedKey(algorithm, seed)
}

func generateKEMKey(algorithm string) (bccsp.Key, error) {
	kem := oqs.KeyEncapsulation{}
	if err := kem.Init(algorithm, nil); err != nil {
		return nil, err
	}
	defer kem.Clean()
	public, err := kem.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &key{algorithm: algorithm, private: true, secret: append([]byte(nil), kem.ExportSecretKey()...), public: public}, nil
}

// KeyImport supports three cases:
//  1. *bccsp.X509PublicKeyImportOpts — the generic contract Fabric's MSP
//     always uses to pull the public key out of an *x509.Certificate,
//     regardless of which BCCSP provider is configured.
//  2. *PrivateKeyImportOpts — this package's own raw-bytes private-key import.
//  3. *PublicKeyImportOpts — this package's own raw-bytes public-key import.
func (c *CSP) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	if opts == nil {
		return nil, errors.New("PQC key-import options are required")
	}

	if _, ok := opts.(*bccsp.X509PublicKeyImportOpts); ok {
		cert, ok := raw.(*x509.Certificate)
		if !ok {
			return nil, errors.New("X509PublicKeyImportOpts requires a *x509.Certificate")
		}
		mldsaPub, ok := cert.PublicKey.(*mldsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate public key is %T, not an ML-DSA key", cert.PublicKey)
		}
		rawBytes := mldsaPub.Bytes()
		algorithm, err := mldsaAlgorithm(rawBytes)
		if err != nil {
			return nil, err
		}
		imported := &key{algorithm: algorithm, public: append([]byte(nil), rawBytes...)}
		if err := validatePublicKey(imported); err != nil {
			return nil, err
		}
		if !opts.Ephemeral() {
			if err := c.store.StoreKey(imported); err != nil {
				return nil, err
			}
		}
		return imported, nil
	}

	data, ok := raw.([]byte)
	if !ok || len(data) == 0 {
		return nil, errors.New("PQC key material must be a non-empty []byte")
	}
	algorithm := opts.Algorithm()
	if !signatureAlgorithms[algorithm] && !kemAlgorithms[algorithm] {
		return nil, fmt.Errorf("unsupported PQC key-import algorithm %q", algorithm)
	}
	var imported *key
	switch opts := opts.(type) {
	case *PrivateKeyImportOpts:
		if len(opts.PublicKey) == 0 {
			return nil, errors.New("public key is required when importing a PQC private key")
		}
		if signatureAlgorithms[algorithm] && len(data) == mldsa.PrivateKeySize {
			// crypto/mldsa seed (e.g. cryptogen PKCS8), not a liboqs secret key.
			seedKey, err := newSeedKey(algorithm, data)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(seedKey.public, opts.PublicKey) {
				return nil, errors.New("public key does not match ML-DSA seed")
			}
			imported = seedKey
		} else {
			imported = &key{algorithm: algorithm, private: true, secret: append([]byte(nil), data...), public: append([]byte(nil), opts.PublicKey...)}
		}
	case *PublicKeyImportOpts:
		public, err := publicKeyImportBytes(algorithm, data)
		if err != nil {
			return nil, err
		}
		imported = &key{algorithm: algorithm, public: public}
	default:
		return nil, errors.New("use PrivateKeyImportOpts or PublicKeyImportOpts")
	}
	if imported.private {
		if err := validatePrivateKey(imported); err != nil {
			return nil, err
		}
	} else if err := validatePublicKey(imported); err != nil {
		return nil, err
	}
	if !opts.Ephemeral() {
		if err := c.store.StoreKey(imported); err != nil {
			return nil, err
		}
	}
	return imported, nil
}

// publicKeyImportBytes returns the raw public key for a PublicKeyImportOpts
// import. Raw bytes are used as given; an ML-DSA key may also be PKIX DER,
// such as public Bytes() or a <ski>_pk file.
func publicKeyImportBytes(algorithm string, data []byte) ([]byte, error) {
	if !signatureAlgorithms[algorithm] {
		return append([]byte(nil), data...), nil
	}
	params, err := mldsaParameters(algorithm)
	if err != nil {
		return nil, err
	}
	if len(data) == params.PublicKeySize() {
		return append([]byte(nil), data...), nil
	}
	parsed, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s public key is neither %d raw bytes nor PKIX DER: %w", algorithm, params.PublicKeySize(), err)
	}
	pub, ok := parsed.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("PKIX public key is %T, not an ML-DSA key", parsed)
	}
	if pub.Parameters() != params {
		return nil, fmt.Errorf("PKIX public key is %s, not %s", pub.Parameters(), algorithm)
	}
	return pub.Bytes(), nil
}

func validatePrivateKey(k *key) error {
	if len(k.seed) > 0 {
		return nil // already validated by mldsa.NewPrivateKey in newSeedKey
	}
	secret := secretCopy(k.secret)
	defer clear(secret)
	if signatureAlgorithms[k.algorithm] {
		sig := oqs.Signature{}
		if err := sig.Init(k.algorithm, secret); err != nil {
			return err
		}
		defer sig.Clean()
		if len(k.secret) != sig.Details().LengthSecretKey {
			return errors.New("invalid ML-DSA secret-key length")
		}
		return nil
	}
	kem := oqs.KeyEncapsulation{}
	if err := kem.Init(k.algorithm, secret); err != nil {
		return err
	}
	defer kem.Clean()
	if len(k.secret) != kem.Details().LengthSecretKey {
		return errors.New("invalid ML-KEM secret-key length")
	}
	return validatePublicKey(k)
}

func validatePublicKey(k *key) error {
	if signatureAlgorithms[k.algorithm] {
		sig := oqs.Signature{}
		if err := sig.Init(k.algorithm, nil); err != nil {
			return err
		}
		defer sig.Clean()
		if len(k.public) != sig.Details().LengthPublicKey {
			return errors.New("invalid ML-DSA public-key length")
		}
		return nil
	}
	kem := oqs.KeyEncapsulation{}
	if err := kem.Init(k.algorithm, nil); err != nil {
		return err
	}
	defer kem.Clean()
	if len(k.public) != kem.Details().LengthPublicKey {
		return errors.New("invalid ML-KEM public-key length")
	}
	return nil
}

func (c *CSP) GetKey(ski []byte) (bccsp.Key, error) { return c.store.GetKey(ski) }

type hashOpts struct{}

func (hashOpts) Algorithm() string     { return "SHA256" }
func (hashOpts) HashFunc() crypto.Hash { return crypto.SHA256 }
func HashOpts() bccsp.HashOpts         { return hashOpts{} }

// newHash returns the hash function selected by opts, as the SW BCCSP does.
// The generic SHA option maps to SHA-256, the SW default (SHA2, level 256).
func newHash(opts bccsp.HashOpts) (hash.Hash, error) {
	if opts == nil {
		return nil, errors.New("invalid opts: must not be nil")
	}
	switch opts.Algorithm() {
	case bccsp.SHA256, bccsp.SHA:
		return sha256.New(), nil
	case bccsp.SHA384:
		return sha512.New384(), nil
	case bccsp.SHA3_256:
		return sha3.New256(), nil
	case bccsp.SHA3_384:
		return sha3.New384(), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm %q", opts.Algorithm())
	}
}

func (c *CSP) Hash(msg []byte, opts bccsp.HashOpts) ([]byte, error) {
	h, err := newHash(opts)
	if err != nil {
		return nil, err
	}
	h.Write(msg)
	return h.Sum(nil), nil
}

func (c *CSP) GetHash(opts bccsp.HashOpts) (hash.Hash, error) { return newHash(opts) }

func (c *CSP) Sign(k bccsp.Key, digest []byte, _ bccsp.SignerOpts) ([]byte, error) {
	key, err := asPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if !signatureAlgorithms[key.algorithm] {
		return nil, errors.New("key is not an ML-DSA signing key")
	}
	if len(key.seed) > 0 {
		params, err := mldsaParameters(key.algorithm)
		if err != nil {
			return nil, err
		}
		sk, err := mldsa.NewPrivateKey(params, key.seed)
		if err != nil {
			return nil, err
		}
		// nil opts: sign the message directly with an empty context, as liboqs does.
		return sk.Sign(nil, digest, nil)
	}
	secret := secretCopy(key.secret)
	defer clear(secret)
	sig := oqs.Signature{}
	if err := sig.Init(key.algorithm, secret); err != nil {
		return nil, err
	}
	defer sig.Clean()
	return sig.Sign(digest)
}

func (c *CSP) Verify(k bccsp.Key, signature, digest []byte, _ bccsp.SignerOpts) (bool, error) {
	key, err := asKey(k)
	if err != nil {
		return false, err
	}
	if !signatureAlgorithms[key.algorithm] {
		return false, errors.New("key is not an ML-DSA verification key")
	}
	params, err := mldsaParameters(key.algorithm)
	if err != nil {
		return false, err
	}
	pub, err := mldsa.NewPublicKey(params, key.public)
	if err != nil {
		return false, fmt.Errorf("invalid %s public key: %w", key.algorithm, err)
	}
	// Verify the bytes exactly as Sign signs them: directly, with an empty
	// context (the MSP passes SHA-256(msg)). With a valid public key, any
	// mldsa.Verify error means the signature does not verify.
	return mldsa.Verify(pub, digest, signature, nil) == nil, nil
}

func (c *CSP) Encapsulate(k bccsp.Key) ([]byte, []byte, error) {
	key, err := asKey(k)
	if err != nil {
		return nil, nil, err
	}
	if !kemAlgorithms[key.algorithm] {
		return nil, nil, errors.New("key is not an ML-KEM key")
	}
	kem := oqs.KeyEncapsulation{}
	if err := kem.Init(key.algorithm, nil); err != nil {
		return nil, nil, err
	}
	defer kem.Clean()
	return kem.EncapSecret(key.public)
}

func (c *CSP) Decapsulate(k bccsp.Key, ciphertext []byte) ([]byte, error) {
	key, err := asPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if !kemAlgorithms[key.algorithm] {
		return nil, errors.New("key is not an ML-KEM key")
	}
	secret := secretCopy(key.secret)
	defer clear(secret)
	kem := oqs.KeyEncapsulation{}
	if err := kem.Init(key.algorithm, secret); err != nil {
		return nil, err
	}
	defer kem.Clean()
	return kem.DecapSecret(ciphertext)
}

// secretCopy returns a copy of a secret key for liboqs. oqs Init keeps the
// slice it is given and Clean wipes it, so liboqs must never see key.secret
// itself. Callers clear the copy when done.
func secretCopy(secret []byte) []byte {
	return append([]byte(nil), secret...)
}

func (c *CSP) Encrypt(bccsp.Key, []byte, bccsp.EncrypterOpts) ([]byte, error) {
	return nil, errors.New("PQC KEMs require Encapsulate, not Encrypt")
}
func (c *CSP) Decrypt(bccsp.Key, []byte, bccsp.DecrypterOpts) ([]byte, error) {
	return nil, errors.New("PQC KEMs require Decapsulate, not Decrypt")
}
func (c *CSP) KeyDeriv(bccsp.Key, bccsp.KeyDerivOpts) (bccsp.Key, error) {
	return nil, errors.New("PQC key derivation is not supported")
}

func asKey(k bccsp.Key) (*key, error) {
	value, ok := k.(*key)
	if !ok || value == nil {
		return nil, errors.New("unsupported PQC key type")
	}
	return value, nil
}
func asPrivateKey(k bccsp.Key) (*key, error) {
	value, err := asKey(k)
	if err != nil {
		return nil, err
	}
	if !value.private {
		return nil, errors.New("private PQC key required")
	}
	return value, nil
}

type FileKeyStore struct {
	path     string
	password []byte
	mu       sync.Mutex
}

func NewFileKeyStore(path string, password []byte) (*FileKeyStore, error) {
	if path == "" {
		return nil, errors.New("key-store path must not be empty")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	return &FileKeyStore{path: path, password: append([]byte(nil), password...)}, nil
}
func (s *FileKeyStore) ReadOnly() bool { return false }

// StoreKey writes ML-DSA private keys as PKCS#8 PEM to <ski>_sk and ML-DSA
// public keys as PKIX PEM to <ski>_pk, as the SW keystore and cryptogen do.
// ML-KEM keys keep the JSON <ski>.pqc format (AES-GCM when a password is
// set), because Go's PKCS#8 has no ML-KEM encoding.
func (s *FileKeyStore) StoreKey(k bccsp.Key) error {
	value, err := asKey(k)
	if err != nil {
		return err
	}
	if signatureAlgorithms[value.algorithm] {
		return s.storeMLDSAKey(value)
	}
	data, err := json.Marshal(storedKey{Algorithm: value.algorithm, Private: value.private, Secret: encode(value.secret), Public: encode(value.public), Seed: encode(value.seed)})
	if err != nil {
		return err
	}
	data, err = s.protect(data)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.WriteFile(filepath.Join(s.path, hex.EncodeToString(value.SKI())+".pqc"), data, 0o600)
}

func (s *FileKeyStore) storeMLDSAKey(k *key) error {
	params, err := mldsaParameters(k.algorithm)
	if err != nil {
		return err
	}
	var block *pem.Block
	var suffix string
	if k.private {
		if len(s.password) > 0 {
			return fmt.Errorf("cannot store %s private key: ML-DSA private keys are stored as unencrypted PKCS#8 PEM, and a keystore password is not supported for them", k.algorithm)
		}
		if len(k.seed) == 0 {
			return fmt.Errorf("cannot store %s private key without its seed: PKCS#8 holds only the FIPS 204 seed, so import an expanded liboqs secret as Temporary", k.algorithm)
		}
		sk, err := mldsa.NewPrivateKey(params, k.seed)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(sk)
		if err != nil {
			return err
		}
		defer clear(der)
		block, suffix = &pem.Block{Type: "PRIVATE KEY", Bytes: der}, "_sk"
	} else {
		pub, err := mldsa.NewPublicKey(params, k.public)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return err
		}
		block, suffix = &pem.Block{Type: "PUBLIC KEY", Bytes: der}, "_pk"
	}
	data := pem.EncodeToMemory(block)
	defer clear(data)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !k.private {
		if s.holdsMLDSAPrivateKey(k.SKI()) {
			return nil
		}
		// The private key may be under another file name, e.g. cryptogen's
		// priv_sk; GetKey's scan would find it only after <ski>_pk.
		if found, err := s.searchKeystoreForSKI(k.SKI()); err == nil {
			clear(found.(*key).seed)
			return nil
		}
	}
	return os.WriteFile(filepath.Join(s.path, hex.EncodeToString(k.SKI())+suffix), data, 0o600)
}

// holdsMLDSAPrivateKey reports whether the private key for ski is already
// stored as <ski>_sk or as a legacy ML-DSA <ski>.pqc. StoreKey then skips
// writing <ski>_pk, which GetKey would read before a legacy .pqc file.
func (s *FileKeyStore) holdsMLDSAPrivateKey(ski []byte) bool {
	name := hex.EncodeToString(ski)
	if _, err := os.Stat(filepath.Join(s.path, name+"_sk")); err == nil {
		return true
	}
	data, err := os.ReadFile(filepath.Join(s.path, name+".pqc"))
	if err != nil {
		return false
	}
	data, err = s.unprotect(data)
	if err != nil {
		return false
	}
	defer clear(data)
	var saved storedKey
	return json.Unmarshal(data, &saved) == nil && saved.Private && signatureAlgorithms[saved.Algorithm]
}

// GetKey looks up <ski>_sk, then <ski>_pk, then the legacy <ski>.pqc, and
// finally scans the keystore for a PKCS#8 ML-DSA key under any file name
// (e.g. cryptogen's priv_sk).
func (s *FileKeyStore) GetKey(ski []byte) (bccsp.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := hex.EncodeToString(ski)
	for _, f := range []struct {
		suffix string
		parse  func([]byte) (*key, error)
	}{{"_sk", parseMLDSAPrivatePEM}, {"_pk", parseMLDSAPublicPEM}} {
		data, err := os.ReadFile(filepath.Join(s.path, name+f.suffix))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		k, err := f.parse(data)
		clear(data)
		if err != nil {
			return nil, fmt.Errorf("%s%s: %w", name, f.suffix, err)
		}
		if !bytes.Equal(k.SKI(), ski) {
			return nil, fmt.Errorf("%s%s holds a key with a different SKI", name, f.suffix)
		}
		return k, nil
	}
	data, err := os.ReadFile(filepath.Join(s.path, name+".pqc"))
	if errors.Is(err, fs.ErrNotExist) {
		return s.searchKeystoreForSKI(ski)
	}
	if err != nil {
		return nil, err
	}
	data, err = s.unprotect(data)
	if err != nil {
		return nil, err
	}
	var saved storedKey
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, err
	}
	return &key{algorithm: saved.Algorithm, private: saved.Private, secret: decode(saved.Secret), public: decode(saved.Public), seed: decode(saved.Seed)}, nil
}

func parseMLDSAPrivatePEM(data []byte) (*key, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("not a PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(block.Bytes)
	if err != nil {
		return nil, err
	}
	sk, ok := parsed.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PKCS#8 key is %T, not an ML-DSA key", parsed)
	}
	algorithm, err := mldsaAlgorithm(sk.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	seed := sk.Bytes()
	defer clear(seed)
	return newSeedKey(algorithm, seed)
}

func parseMLDSAPublicPEM(data []byte) (*key, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("not a PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("PKIX key is %T, not an ML-DSA key", parsed)
	}
	algorithm, err := mldsaAlgorithm(pub.Bytes())
	if err != nil {
		return nil, err
	}
	return &key{algorithm: algorithm, public: pub.Bytes()}, nil
}

// searchKeystoreForSKI scans the keystore for a PKCS8 PEM ML-DSA private key
// (e.g. cryptogen's priv_sk) whose SKI matches. It never writes to the keystore.
func (s *FileKeyStore) searchKeystoreForSKI(ski []byte) (bccsp.Key, error) {
	entries, _ := os.ReadDir(s.path)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Size() > (1<<16) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.path, entry.Name()))
		if err != nil {
			continue
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			continue
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			continue
		}
		sk, ok := parsed.(*mldsa.PrivateKey)
		if !ok {
			continue
		}
		algorithm, err := mldsaAlgorithm(sk.PublicKey().Bytes())
		if err != nil {
			continue
		}
		found, err := newSeedKey(algorithm, sk.Bytes())
		if err != nil || !bytes.Equal(found.SKI(), ski) {
			continue
		}
		return found, nil
	}
	return nil, fmt.Errorf("key with SKI %x not found in %s", ski, s.path)
}

type storedKey struct {
	Algorithm string `json:"algorithm"`
	Private   bool   `json:"private"`
	Secret    string `json:"secret,omitempty"`
	Public    string `json:"public"`
	Seed      string `json:"seed,omitempty"`
}

func encode(v []byte) string { return base64.RawStdEncoding.EncodeToString(v) }
func decode(v string) []byte { result, _ := base64.RawStdEncoding.DecodeString(v); return result }

func (s *FileKeyStore) protect(data []byte) ([]byte, error) {
	if len(s.password) == 0 {
		return data, nil
	}
	key := sha256.Sum256(s.password)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (s *FileKeyStore) unprotect(data []byte) ([]byte, error) {
	if len(s.password) == 0 {
		return data, nil
	}
	key := sha256.Sum256(s.password)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("invalid encrypted key")
	}
	return gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
}

func PublicKeyBytes(k bccsp.Key) ([]byte, error) {
	value, err := asKey(k)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), value.public...), nil
}

func Algorithm(k bccsp.Key) (string, error) {
	value, err := asKey(k)
	if err != nil {
		return "", err
	}
	return value.algorithm, nil
}