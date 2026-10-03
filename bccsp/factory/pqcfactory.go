//go:build pqc
// +build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"github.com/hyperledger/fabric-lib-go/bccsp"
	pqc "github.com/hyperledger/fabric-lib-go/bccsp-pqc"
	"github.com/pkg/errors"
)

const (
	// PQCBasedFactoryName is the name of the post-quantum BCCSP implementation.
	PQCBasedFactoryName = "PQC"
)

type PQCFactory struct{}

func newPQCFactory() BCCSPFactory {
	return &PQCFactory{}
}

func (f *PQCFactory) Name() string { return PQCBasedFactoryName }

func (f *PQCFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	if config == nil || config.PQC == nil {
		return nil, errors.New("invalid config: PQC options must not be nil")
	}
	if config.PQC.KeyStorePath == "" {
		return nil, errors.New("invalid config: PQC key store path must not be empty")
	}

	return pqc.NewWithFileKeyStore(config.PQC.KeyStorePath, config.PQC.Password)
}
