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
	GetClientID() (int32, error)
	GetManufacturingConfig() ([]byte, error)
	GetExtension() ([]*ExtensionDevice, error)
	GetTBBRoTPK() ([]*TBBRoTPKItem, error)
	GetPeerSigners() ([]byte, error)

	SetConfig([]byte) error
	SetHashAlgID(string) error
	SetClientID(int32) error
	SetManufacturingConfig([]byte) error
	SetExtension([]*ExtensionDevice) error
	SetTBBRoTPK([]*TBBRoTPKItem) error
	SetPeerSigners([]byte) error
}

func NewClaimsWithProfile(profileName string) (IClaims, error) {
	icPsa, err := psatoken.NewClaims(profileName)
	if err != nil {
		return nil, err
	}

	ic, ok := icPsa.(IClaims)
	if !ok {
		return nil, fmt.Errorf("%s is not a CCA platform profile", profileName)
	}

	return ic, nil
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

	profile, err := c.GetProfile()
	if err != nil {
		return fmt.Errorf("could not get profile: %w", err)
	}

	if profile == "tag:arm.com,2024:cca_platform#2.0.0" {
		if err := psatoken.FilterError(c.GetClientID()); err != nil {
			return fmt.Errorf("validating platform client id: %w", err)
		}

		if err := psatoken.FilterError(c.GetManufacturingConfig()); err != nil {
			return fmt.Errorf("validating platform manufacturing config: %w", err)
		}

		if err := psatoken.FilterError(c.GetExtension()); err != nil {
			return fmt.Errorf("validating platform extension: %w", err)
		}

		if err := psatoken.FilterError(c.GetTBBRoTPK()); err != nil {
			return fmt.Errorf("validating platform TBB ROTPK: %w", err)
		}

		if err := psatoken.FilterError(c.GetPeerSigners()); err != nil {
			return fmt.Errorf("validating platform peer signers: %w", err)
		}

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
