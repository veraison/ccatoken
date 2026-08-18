// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package realm

import (
	"fmt"

	"github.com/veraison/psatoken"
)

const ProfileNameV2 = "tag:arm.com,2024:realm#2.0.0"

// ProfileV2 is the IProfile implementation for CCA realm claims
// for "tag:arm.com,2024:realm#2.0.0".
// It is registered to associate the claims with the profile name,
// so that it can be automatically used during unmarshaling.
type ProfileV2 struct{}

func (o ProfileV2) GetName() string {
	return ProfileNameV2
}

func (o ProfileV2) GetClaims() IClaims {
	return newClaimsV2()
}

func (o ProfileV2) GetUninitializedClaims() IClaims {
	return &ClaimsV2{}
}

// ClaimsV2 contains the CCA realm claims for "tag:arm.com,2024:realm#2.0.0".
// It implements IClaims, which is an extension of psatoken.IClaims.
type ClaimsV2 struct {
	Claims
	MECPolicy *MECPolicy `cbor:"44243,keyasint" json:"cca-realm-mec-policy,omitempty"`
}

type MECPolicy string

const (
	MECPolicyPrivate MECPolicy = "private"
	MECPolicyShared  MECPolicy = "shared"
)

// ValidateMECPolicy checks if the provided MEC policy is valid (either "private" or "shared").
func ValidateMECPolicy(v MECPolicy) error {
	if v != MECPolicyPrivate && v != MECPolicyShared {
		return fmt.Errorf("%w: MEC policy MUST be 'private' or 'shared'", psatoken.ErrWrongSyntax)
	}
	return nil
}

// SetMECPolicy sets the MEC policy claim,
// which must be either "private" or "shared". It returns an error if the provided value is invalid.
func (c *ClaimsV2) SetMECPolicy(v MECPolicy) error {
	err := ValidateMECPolicy(v)
	if err != nil {
		return err
	}

	c.MECPolicy = &v
	return nil
}

// GetMECPolicy returns the MEC policy claim,
// which must be either "private" or "shared". It returns an error if the claim is missing or invalid.
func (c *ClaimsV2) GetMECPolicy() (MECPolicy, error) {
	v := c.MECPolicy
	if v == nil {
		return "", psatoken.ErrMandatoryClaimMissing
	}

	err := ValidateMECPolicy(*v)
	if err != nil {
		return "", err
	}

	return *v, nil
}

// GetProfile returns the profile, which is mandatory and
// expected to be "tag:arm.com,2024:realm#2.0.0" for ClaimsV2.
func (c *ClaimsV2) GetProfile() (string, error) {
	if c.Profile == nil {
		return "", psatoken.ErrMandatoryClaimMissing
	}

	profileString, err := c.Profile.Get()
	if err != nil {
		return "", err
	}

	if profileString != ProfileNameV2 {
		return "", fmt.Errorf("%w: expecting %q, got %q",
			psatoken.ErrWrongProfile, ProfileNameV2, profileString)
	}

	return profileString, nil
}

func newClaimsV2() IClaims {
	// Create a Claims V1 object though with the V2 profile name
	baseClaims := newClaimsV1(ProfileNameV2).(*Claims)

	// Create and return a Claims V2 object
	return &ClaimsV2{
		Claims:    *baseClaims,
		MECPolicy: nil,
	}
}

// Semantic validation
func (c *ClaimsV2) Validate() error {
	return ValidateClaims(c)
}
