// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package realm

import (
	"encoding/json"
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
	GetProfile() (string, error)

	// Setters
	SetChallenge([]byte) error
	SetPersonalizationValue([]byte) error
	SetInitialMeasurement([]byte) error
	SetExtensibleMeasurements([][]byte) error
	SetHashAlgID(string) error
	SetPubKey([]byte) error
	SetPubKeyHashAlgID(string) error
}

// DecodeAndValidateClaimsFromCBOR unmarshals and validates CCA realm claims
// from provided CBOR data.
func DecodeAndValidateClaimsFromCBOR(buf []byte) (IClaims, error) {
	cl, err := DecodeClaimsFromCBOR(buf)
	if err != nil {
		return nil, err
	}

	if err := cl.Validate(); err != nil {
		return nil, err
	}

	return cl, nil
}

// DecodeClaimsFromCBOR unmarshals CCA realm claims from provided CBOR data.
func DecodeClaimsFromCBOR(buf []byte) (IClaims, error) {
	cl := newClaimsForDecoding()

	if err := dm.Unmarshal(buf, cl); err != nil {
		return nil, err
	}

	return cl, nil
}

// DecodeAndValidateClaimsFromJSON unmarshals and validates CCA realm claims
// from provided JSON data.
func DecodeAndValidateClaimsFromJSON(buf []byte) (IClaims, error) {
	cl, err := DecodeClaimsFromJSON(buf)
	if err != nil {
		return nil, err
	}

	if err := cl.Validate(); err != nil {
		return nil, err
	}

	return cl, nil
}

// DecodeClaimsFromJSON unmarshals CCA realm claims from provided JSON data.
func DecodeClaimsFromJSON(buf []byte) (IClaims, error) {
	cl := NewClaims()

	if err := json.Unmarshal(buf, cl); err != nil {
		return nil, err
	}

	return cl, nil
}

// ValidateAndEncodeClaimsToCBOR validates and then marshals CCA realm claims
// to CBOR.
func ValidateAndEncodeClaimsToCBOR(c IClaims) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	return EncodeClaimsToCBOR(c)
}

// EncodeClaimsToCBOR marshals CCA realm claims to CBOR.
func EncodeClaimsToCBOR(c IClaims) ([]byte, error) {
	if c == nil {
		return nil, nil
	}

	return em.Marshal(c)
}

// ValidateAndEncodeClaimsToJSON validates and then marshals CCA realm claims
// to JSON.
func ValidateAndEncodeClaimsToJSON(c IClaims) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	return EncodeClaimsToJSON(c)
}

// EncodeClaimsToJSON marshals CCA realm claims to JSON.
func EncodeClaimsToJSON(c IClaims) ([]byte, error) {
	if c == nil {
		return nil, nil
	}

	return json.Marshal(c)
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
