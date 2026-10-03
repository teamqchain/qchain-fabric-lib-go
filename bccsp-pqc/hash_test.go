/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pqc

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
)

func TestHashHonoursOpts(t *testing.T) {
	msg := []byte("bccsp-pqc hash test")
	sha256Sum := sha256.Sum256(msg)
	sha384Sum := sha512.Sum384(msg)
	sha3256Sum := sha3.Sum256(msg)
	sha3384Sum := sha3.Sum384(msg)
	tests := []struct {
		name string
		opts bccsp.HashOpts
		want []byte
	}{
		{"SHA256", &bccsp.SHA256Opts{}, sha256Sum[:]},
		{"SHA384", &bccsp.SHA384Opts{}, sha384Sum[:]},
		{"SHA3_256", &bccsp.SHA3_256Opts{}, sha3256Sum[:]},
		{"SHA3_384", &bccsp.SHA3_384Opts{}, sha3384Sum[:]},
		{"generic SHA defaults to SHA256", &bccsp.SHAOpts{}, sha256Sum[:]},
		{"package HashOpts is SHA256", HashOpts(), sha256Sum[:]},
	}
	csp := &CSP{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := csp.Hash(msg, tt.opts)
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("Hash = %x, want %x", got, tt.want)
			}
			h, err := csp.GetHash(tt.opts)
			if err != nil {
				t.Fatalf("GetHash: %v", err)
			}
			h.Write(msg)
			if got := h.Sum(nil); !bytes.Equal(got, tt.want) {
				t.Fatalf("GetHash sum = %x, want %x", got, tt.want)
			}
		})
	}
}

type unknownHashOpts struct{}

func (unknownHashOpts) Algorithm() string { return "MD5" }

func TestHashRejectsBadOpts(t *testing.T) {
	csp := &CSP{}
	if _, err := csp.Hash([]byte("x"), nil); err == nil {
		t.Fatal("Hash accepted nil opts")
	}
	if _, err := csp.GetHash(nil); err == nil {
		t.Fatal("GetHash accepted nil opts")
	}
	if _, err := csp.Hash([]byte("x"), unknownHashOpts{}); err == nil {
		t.Fatal("Hash accepted an unknown algorithm")
	}
	if _, err := csp.GetHash(unknownHashOpts{}); err == nil {
		t.Fatal("GetHash accepted an unknown algorithm")
	}
}
