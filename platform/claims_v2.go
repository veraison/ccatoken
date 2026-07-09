// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"encoding/json"
	"fmt"

	"github.com/veraison/psatoken"
)

const ProfileNameV2 = "tag:arm.com,2024:cca_platform#2.0.0"

// Profile is the psatoken.IProfile implementation for CCA claims. It is
// registered to associate the claims with the profile name, so that it can be
// automatically used during unmarshaling.
type ProfileV2 struct{}

func (o ProfileV2) GetName() string {
	return ProfileNameV2
}

func (o ProfileV2) GetClaims() psatoken.IClaims {
	return NewClaimsV2()
}

// Claims contains the CCA platform claims. It implements IClaims, which is an
// extension of psatoken.IClaims.
type ClaimsV2 struct {
	Claims
	ClientID            *int32         `cbor:"2394,keyasint" json:"cca-platform-client-id"`
	ManufacturingConfig *[]byte        `cbor:"2403,keyasint,omitempty" json:"cca-platform-manufacturing-config,omitempty"`
	TBBRoTPK            *TBBRoTPKItems `cbor:"2405,keyasint,omitempty" json:"cca-platform-tbb-rotpk,omitempty"`
	PeerSigners         *[]byte        `cbor:"2406,keyasint,omitempty" json:"cca-platform-peer-signers,omitempty"`
	// Extension  *TODO		`cbor:"2404,keyasint,omitempty" json:"cca-platform-extension,omitempty"` // to find out the type
}

// NewClaims claims returns a new instance of Claims.
func NewClaimsV2() IClaims {
	baseClaims := newClaims(ProfileNameV2).(*Claims)

	return &ClaimsV2{
		Claims:   *baseClaims,
		TBBRoTPK: &TBBRoTPKItems{},
	}
}

// Semantic validation
func (c *ClaimsV2) Validate() error {
	if err := ValidateClaims(c); err != nil {
		return err
	}

	if err := psatoken.FilterError(c.GetManufacturingConfig()); err != nil {
		return fmt.Errorf("validating platform manufacturing config: %w", err)
	}

	if err := psatoken.FilterError(c.GetTBBRoTPK()); err != nil {
		return fmt.Errorf("validating platform TBB ROTPK: %w", err)
	}

	if err := psatoken.FilterError(c.GetPeerSigners()); err != nil {
		return fmt.Errorf("validating platform peer signers: %w", err)
	}

	return nil
}

// Codecs

// this type alias is used to prevent infinite recursion during marshaling.
type claimsV2 ClaimsV2

// UnmarshalCBOR decodes the claims from CBOR
func (c *ClaimsV2) UnmarshalCBOR(buf []byte) error {
	c.Profile = nil // clear profile to make sure we taked it from buf

	return dm.Unmarshal(buf, (*claimsV2)(c))
}

// MarshalCBOR encodes the claims to CBOR
func (c ClaimsV2) MarshalCBOR() ([]byte, error) {
	if c.SwComponents != nil && c.SwComponents.IsEmpty() {
		c.SwComponents = nil
	}
	if c.TBBRoTPK != nil && c.TBBRoTPK.IsEmpty() {
		c.TBBRoTPK = nil
	}

	return em.Marshal((*claimsV2)(&c))
}

// UnmarshalJSON decodes the claims from JSON
func (c *ClaimsV2) UnmarshalJSON(buf []byte) error {
	c.Profile = nil // clear profile to make sure we taked it from buf

	return json.Unmarshal(buf, (*claimsV2)(c))
}

// MarshalJSON encodes the claims into JSON
func (c ClaimsV2) MarshalJSON() ([]byte, error) {
	if c.SwComponents != nil && c.SwComponents.IsEmpty() {
		c.SwComponents = nil
	}
	if c.TBBRoTPK != nil && c.TBBRoTPK.IsEmpty() {
		c.TBBRoTPK = nil
	}

	return json.Marshal((*claimsV2)(&c))
}

func (c *ClaimsV2) SetClientID(v int32) error {
	if v != 1 {
		return fmt.Errorf("%w: client id MUST be 1", psatoken.ErrWrongSyntax)
	}

	clientID := int32(v)
	c.ClientID = &clientID

	return nil
}

func (c *ClaimsV2) SetManufacturingConfig(v []byte) error {
	if len(v) == 0 {
		return fmt.Errorf("%w: manufacturing config", psatoken.ErrWrongSyntax)
	}

	c.ManufacturingConfig = &v

	return nil
}

func (c *ClaimsV2) SetTBBRoTPK(vals []ITBBRoTPKItem) error {
	if c.TBBRoTPK == nil {
		c.TBBRoTPK = &TBBRoTPKItems{}
	}

	return c.TBBRoTPK.Replace(vals)
}

func (c *ClaimsV2) SetPeerSigners(v []byte) error {
	if len(v) == 0 {
		return fmt.Errorf("%w: peer signers", psatoken.ErrWrongSyntax)
	}

	c.PeerSigners = &v

	return nil
}

func (c *ClaimsV2) GetClientID() (int32, error) {
	if c.ClientID == nil {
		return 0, psatoken.ErrMandatoryClaimMissing
	}

	return *c.ClientID, nil
}

func (c *ClaimsV2) GetManufacturingConfig() ([]byte, error) {
	if c.ManufacturingConfig == nil {
		return nil, psatoken.ErrOptionalClaimMissing
	}

	if len(*c.ManufacturingConfig) == 0 {
		return nil, fmt.Errorf("%w: manufacturing config", psatoken.ErrWrongSyntax)
	}

	return *c.ManufacturingConfig, nil
}

func (c *ClaimsV2) GetTBBRoTPK() ([]ITBBRoTPKItem, error) {
	if c.TBBRoTPK == nil || c.TBBRoTPK.IsEmpty() {
		return nil, psatoken.ErrOptionalClaimMissing
	}

	return c.TBBRoTPK.Values()
}

func (c *ClaimsV2) GetPeerSigners() ([]byte, error) {
	if c.PeerSigners == nil {
		return nil, psatoken.ErrOptionalClaimMissing
	}

	if len(*c.PeerSigners) == 0 {
		return nil, fmt.Errorf("%w: peer signers", psatoken.ErrWrongSyntax)
	}

	return *c.PeerSigners, nil
}
