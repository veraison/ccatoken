// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"fmt"

	"github.com/veraison/psatoken"
)

// IClaims extends psatoken.IClaims to add accessors for CCA  claims.
type IClaims interface {
	psatoken.IClaims

	GetConfig() ([]byte, error)
	GetHashAlgID() (string, error)

	SetConfig([]byte) error
	SetHashAlgID(string) error
}

// DecodeClaims unmarshals CCA platform claims from provided CBOR data.
func DecodeClaims(buf []byte) (IClaims, error) {
	cl := NewClaims()

	if err := cl.FromCBOR(buf); err != nil {
		return nil, err
	}

	return cl, nil
}

// ValidateClaims returns an error if the provided IClaims instance does not
// contain a valid set of CCA platform claims.
func ValidateClaims(c IClaims) error {
	if err := psatoken.ValidateClaims(c); err != nil {
		return err
	}

	if err := psatoken.FilterError(c.GetConfig()); err != nil {
		return fmt.Errorf("validating platform config: %w", err)
	}

	if err := psatoken.FilterError(c.GetHashAlgID()); err != nil {
		return fmt.Errorf("validating platform hash algo id: %w", err)
	}

	return nil
}
