// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package realm

import (
	"fmt"

	"github.com/veraison/psatoken"
)

// IClaims provides a uniform interface for dealing with CCA realm claims
type IClaims interface {
	psatoken.IClaimsBase

	// Getters
	GetChallenge() ([]byte, error)
	GetPersonalizationValue() ([]byte, error)
	GetInitialMeasurement() ([]byte, error)
	GetExtensibleMeasurements() ([][]byte, error)
	GetHashAlgID() (string, error)
	GetPubKey() ([]byte, error)
	GetPubKeyHashAlgID() (string, error)

	// Setters
	SetChallenge([]byte) error
	SetPersonalizationValue([]byte) error
	SetInitialMeasurement([]byte) error
	SetExtensibleMeasurements([][]byte) error
	SetHashAlgID(string) error
	SetPubKey([]byte) error
	SetPubKeyHashAlgID(string) error
}

// NewClaims returns a new instance of platform Claims.
func NewClaims() IClaims {
	return &Claims{}
}

// DecodeClaims unmarshals CCA realm claims from provided CBOR data.
func DecodeClaims(buf []byte) (IClaims, error) {
	cl := &Claims{}

	if err := cl.FromCBOR(buf); err != nil {
		return nil, err
	}

	return cl, nil
}

// ValidateClaims returns an error if the provided IClaims instance does not
// contain a valid set of CCA realm claims.
func ValidateClaims(c IClaims) error {
	if err := psatoken.FilterError(c.GetChallenge()); err != nil {
		return fmt.Errorf("validating realm challenge claim: %w", err)
	}

	if err := psatoken.FilterError(c.GetPersonalizationValue()); err != nil {
		return fmt.Errorf("validating realm personalization value claim: %w", err)
	}

	if err := psatoken.FilterError(c.GetInitialMeasurement()); err != nil {
		return fmt.Errorf("validating realm initial measurements claim: %w", err)
	}

	if err := psatoken.FilterError(c.GetExtensibleMeasurements()); err != nil {
		return fmt.Errorf("validating realm extended measurements claim: %w", err)
	}

	if err := psatoken.FilterError(c.GetHashAlgID()); err != nil {
		return fmt.Errorf("validating realm hash alg ID claim: %w", err)
	}

	if err := psatoken.FilterError(c.GetPubKey()); err != nil {
		return fmt.Errorf("validating realm public key claim: %w", err)
	}

	if err := psatoken.FilterError(c.GetPubKeyHashAlgID()); err != nil {
		return fmt.Errorf("validating realm public key hash alg ID claim: %w", err)
	}
	return nil
}
