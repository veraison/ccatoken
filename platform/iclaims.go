// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"encoding/json"
	"errors"
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

// DecodeAndValidateClaimsFromCBOR unmarshals and validates CCA platform claims
// from provided CBOR buf.
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

// DecodeClaimsFromCBOR unmarshals CCA platform claims from provided CBOR buf.
func DecodeClaimsFromCBOR(buf []byte) (IClaims, error) {
	i, err := psatoken.DecodeClaimsFromCBOR(buf)
	if err != nil {
		return nil, err
	}

	ic, ok := i.(IClaims)
	if !ok {
		return nil, errors.New("not a CCA platform token")
	}

	return ic, nil
}

// DecodeAndValidateClaimsFromJSON unmarshals and validates CCA platform claims
// from provided JSON buf.
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

// DecodeClaimsFromJSON unmarshals CCA platform claims from provided JSON buf.
func DecodeClaimsFromJSON(buf []byte) (IClaims, error) {
	i, err := psatoken.DecodeClaimsFromJSON(buf)
	if err != nil {
		return nil, err
	}

	ic, ok := i.(IClaims)
	if !ok {
		return nil, errors.New("not a (JSON-encoded) CCA platform token")
	}

	return ic, nil
}

// ValidateAndEncodeClaimsToCBOR validates and then marshals CCA platform claims
// to CBOR.
func ValidateAndEncodeClaimsToCBOR(c IClaims) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	return EncodeClaimsToCBOR(c)
}

// EncodeClaimsToCBOR marshals CCA platform claims to CBOR.
func EncodeClaimsToCBOR(c IClaims) ([]byte, error) {
	if c == nil {
		return nil, nil
	}

	return em.Marshal(c)
}

// ValidateAndEncodeClaimsToJSON validates and then marshals CCA platform claims
// to JSON.
func ValidateAndEncodeClaimsToJSON(c IClaims) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	return EncodeClaimsToJSON(c)
}

// EncodeClaimsToJSON marshals CCA platform claims to JSON.
func EncodeClaimsToJSON(c IClaims) ([]byte, error) {
	if c == nil {
		return nil, nil
	}

	return json.Marshal(c)
}
