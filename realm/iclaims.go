// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package realm

import (
	"fmt"
)

// IClaims provides a uniform interface for dealing with CCA realm claims
type IClaims interface {
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

	// CBOR codecs
	FromCBOR([]byte) error
	ToCBOR() ([]byte, error)
	FromUnvalidatedCBOR([]byte) error
	ToUnvalidatedCBOR() ([]byte, error)

	// JSON codecs
	FromJSON([]byte) error
	ToJSON() ([]byte, error)
	FromUnvalidatedJSON([]byte) error
	ToUnvalidatedJSON() ([]byte, error)

	// Semantic validation
	Validate() error
}

func NewClaims() IClaims {
	return &Claims{}
}

func DecodeClaims(buf []byte) (IClaims, error) {
	cl := &Claims{}

	if err := cl.FromCBOR(buf); err != nil {
		return nil, err
	}

	return cl, nil
}

func validate(c IClaims) error {
	// realm challenge
	_, err := c.GetChallenge()
	if err != nil {
		return fmt.Errorf("validating cca-realm-challenge claim: %w", err)
	}

	// cca personalization value
	_, err = c.GetPersonalizationValue()
	if err != nil {
		return fmt.Errorf("validating cca-realm-personalization value claim: %w", err)
	}

	// initial measurements
	if _, err := c.GetInitialMeasurement(); err != nil {
		return fmt.Errorf("validating cca-realm-initial-measurements claim: %w", err)
	}

	// extensible measurements
	if _, err := c.GetExtensibleMeasurements(); err != nil {
		return fmt.Errorf("validating cca-realm-extended-measurements claim: %w", err)
	}

	// hash algorim id
	if _, err := c.GetHashAlgID(); err != nil {
		return fmt.Errorf("validating cca-realm-hash-alg-id claim: %w", err)
	}

	// public key
	if _, err := c.GetPubKey(); err != nil {
		return fmt.Errorf("validating cca-realm-public-key claim: %w", err)
	}

	// hash algorithm id for public key
	if _, err := c.GetPubKeyHashAlgID(); err != nil {
		return fmt.Errorf("validating cca-realm-public-key-hash-alg-id claim: %w", err)
	}
	return nil
}
