// Copyright 2021-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package realm

import (
	"encoding/json"
	"fmt"

	"github.com/veraison/eat"
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
	GetMECPolicy() (MECPolicy, error)
	GetProfile() (string, error)

	// Setters
	SetChallenge([]byte) error
	SetPersonalizationValue([]byte) error
	SetInitialMeasurement([]byte) error
	SetExtensibleMeasurements([][]byte) error
	SetHashAlgID(string) error
	SetPubKey([]byte) error
	SetPubKeyHashAlgID(string) error
	SetMECPolicy(MECPolicy) error
}

// NewClaimsWithProfile returns a new IClaims instance for the specified profile name.
// If this name does not match a registered profile, an error is returned.
// If an empty string is provided, the default profile is used.
func NewClaimsWithProfile(profileName string) (IClaims, error) {
	entry, ok := profilesRegister[profileName]
	if !ok {
		return nil, fmt.Errorf("unsupported profile %q", profileName)
	}

	return entry.Profile.GetClaims(), nil
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
	selector := struct {
		// note: code point 265 is defined as the CCA realm profile's EAT profile label. See
		// https://www.ietf.org/archive/id/draft-ffm-rats-cca-token-03.html#name-realm-profile-definition.
		Profile *eat.Profile `cbor:"265,keyasint"`
	}{}

	err := dm.Unmarshal(buf, &selector)
	if err != nil {
		return nil, err
	}

	profileName := ""
	if selector.Profile != nil {
		profileName, err = selector.Profile.Get()
		if err != nil {
			return nil, err
		}
	}

	entry, ok := profilesRegister[profileName]
	if !ok {
		return nil, fmt.Errorf("unknown profile: %q", profileName)
	}

	claims := entry.Profile.GetUninitializedClaims()

	if err := dm.Unmarshal(buf, claims); err != nil {
		return nil, err
	}

	return claims, nil
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
	var decoded map[string]interface{}
	if err := json.Unmarshal(buf, &decoded); err != nil {
		return nil, err
	}
	var found IProfile
	jsonTagMatched := false
	jsonTagMatchedValue := ""

	for name, entry := range profilesRegister {
		profileTag, ok := decoded[entry.JSONTag]
		if !ok {
			continue
		}

		jsonTagMatched = true
		profileName, ok := profileTag.(string)
		if !ok {
			return nil, fmt.Errorf("profile %q must be a string", entry.JSONTag)
		}
		jsonTagMatchedValue = profileName

		if profileName != entry.Profile.GetName() {
			continue
		}

		if found != nil && found.GetName() != entry.Profile.GetName() {
			return nil, fmt.Errorf("matched multiple profiles: %s and %s",
				name, found.GetName())
		}

		found = entry.Profile
	}

	if found == nil {
		if jsonTagMatched {
			// Another profile with the same JSON tag (e.g. cca-realm-profile) has been registered,
			// but this profile name is unrecognized.
			return nil, fmt.Errorf(`unknown profile: %q`, jsonTagMatchedValue)
		}
		if defaultEntry, ok := profilesRegister[""]; ok {
			// Either no profile claim is set,
			// or a profile claim is set but the profile has not been registered
			// and furthermore no profile with the same JSON tag has been registered.
			// Unfortunately, we are not able to differentiate between these two cases.
			// We return the default profile (V1),which covers legacy tokens that don't include a realm profile claim.
			found = defaultEntry.Profile
		} else {
			// Should not happen, as we register a default profile (V1) in init()
			return nil, fmt.Errorf("no profile claim was found and no default profile is registered")
		}
	}

	claims := found.GetUninitializedClaims()

	if err := json.Unmarshal(buf, claims); err != nil {
		return nil, err
	}

	return claims, nil
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
	if err := psatoken.FilterError(c.GetProfile()); err != nil {
		return fmt.Errorf("validating realm profile claim: %w", err)
	}

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

	// New claim in V2. V1 Claims returns ErrClaimNotInProfile, which is ignored by FilterError.
	if err := psatoken.FilterError(c.GetMECPolicy()); err != nil {
		return fmt.Errorf("validating realm MEC policy claim: %w", err)
	}
	return nil
}

func init() {
	if err := registerDefaultProfile(Profile{}); err != nil {
		panic(err)
	}

	if err := RegisterProfile(Profile{}); err != nil {
		panic(err)
	}

	if err := RegisterProfile(ProfileV2{}); err != nil {
		panic(err)
	}
}
