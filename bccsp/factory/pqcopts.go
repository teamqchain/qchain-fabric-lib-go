/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

// PQCOpts contains options for the PQCFactory.
type PQCOpts struct {
	KeyStorePath string `json:"keyStorePath" yaml:"KeyStorePath"`
	Password     []byte `json:"password,omitempty" yaml:"Password,omitempty"`
}
