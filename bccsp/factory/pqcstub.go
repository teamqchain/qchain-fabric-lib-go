//go:build !pqc
// +build !pqc

package factory

func newPQCFactory() BCCSPFactory {
	return nil
}
