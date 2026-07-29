// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"encoding/json"
	"fmt"

	"github.com/veraison/psatoken"
)

const ProfileNameV2 = "tag:arm.com,2024:cca_platform#2.0.0"

// ProfileV2 is the psatoken.IProfile implementation for CCA claims (2024/2.0.0; draft-ffm-rats-cca-token/03).
// It is registered to associate the claims with the profile name, so that it can be
// automatically used during unmarshaling.
type ProfileV2 struct{}

func (o ProfileV2) GetName() string {
	return ProfileNameV2
}

func (o ProfileV2) GetClaims() psatoken.IClaims {
	return newClaimsV2()
}

type addedClaimsV2 struct {
	ClientID            *int32         `cbor:"2394,keyasint" json:"cca-platform-client-id"`
	ManufacturingConfig *[]byte        `cbor:"2403,keyasint,omitempty" json:"cca-platform-manufacturing-config,omitempty"`
	TBBRoTPK            *TBBRoTPKItems `cbor:"2405,keyasint,omitempty" json:"cca-platform-tbb-rotpk,omitempty"`
	PeerSigners         *[]byte        `cbor:"2406,keyasint,omitempty" json:"cca-platform-peer-signers,omitempty"`
	// Extension  *TODO		`cbor:"2404,keyasint,omitempty" json:"cca-platform-extension,omitempty"` // to find out the type
}

// ClaimsV2 contains the CCA platform claims for tag:arm.com,2024:cca_platform#2.0.0.
// It implements IClaims, which is an extension of psatoken.IClaims.
type ClaimsV2 struct {
	Claims
	addedClaimsV2
}

// This type is used to prevent infinite recursion during marshaling.
// It has the same fields as ClaimsV2, but no methods.
// Crucially, it does not have Marshal/Unmarshal JSON/CBOR methods inherited from Claims,
// which would interfere with json.Marshal and json.Unmarshal.
type plainClaimsV2 struct {
	claims
	addedClaimsV2
}

func toPlainClaimsV2(c *ClaimsV2) plainClaimsV2 {
	return plainClaimsV2{
		claims:        claims(c.Claims),
		addedClaimsV2: c.addedClaimsV2,
	}
}

func fromPlainClaimsV2(c *plainClaimsV2) ClaimsV2 {
	return ClaimsV2{
		Claims:        Claims(c.claims),
		addedClaimsV2: c.addedClaimsV2,
	}
}

func newClaimsV2() IClaims {
	// Create a Claims V1 object though with the V2 profile name
	baseClaims := newClaimsV1(ProfileNameV2).(*Claims)

	// Create and return a Claims V2 object
	return &ClaimsV2{
		Claims:        *baseClaims,
		addedClaimsV2: addedClaimsV2{},
	}
}

// Semantic validation
func (c *ClaimsV2) Validate() error {
	return ValidateClaims(c)
}

// Codecs

// UnmarshalCBOR decodes the claims from CBOR
func (c *ClaimsV2) UnmarshalCBOR(buf []byte) error {
	c.Profile = nil // clear profile to make sure we took it from buf

	cV2 := toPlainClaimsV2((newClaimsV2().(*ClaimsV2)))
	if err := dm.Unmarshal(buf, &cV2); err != nil {
		return err
	}

	*c = fromPlainClaimsV2(&cV2)

	return nil
}

// MarshalCBOR encodes the claims to CBOR
func (c ClaimsV2) MarshalCBOR() ([]byte, error) {
	if c.SwComponents != nil && c.SwComponents.IsEmpty() {
		c.SwComponents = nil
	}
	if c.TBBRoTPK != nil && c.TBBRoTPK.IsEmpty() {
		c.TBBRoTPK = nil
	}

	cv2 := toPlainClaimsV2(&c)

	return em.Marshal(&cv2)
}

// UnmarshalJSON decodes the claims from JSON
func (c *ClaimsV2) UnmarshalJSON(buf []byte) error {
	c.Profile = nil // clear profile to make sure we took it from buf

	cV2 := toPlainClaimsV2((newClaimsV2().(*ClaimsV2)))
	if err := json.Unmarshal(buf, &cV2); err != nil {
		return err
	}
	*c = fromPlainClaimsV2(&cV2)

	return nil
}

// MarshalJSON encodes the claims into JSON
func (c ClaimsV2) MarshalJSON() ([]byte, error) {
	if c.SwComponents != nil && c.SwComponents.IsEmpty() {
		c.SwComponents = nil
	}
	if c.TBBRoTPK != nil && c.TBBRoTPK.IsEmpty() {
		c.TBBRoTPK = nil
	}

	cv2 := toPlainClaimsV2(&c)

	return json.Marshal(&cv2)
}

func (c *ClaimsV2) SetClientID(v int32) error {
	if v != 1 {
		return fmt.Errorf("%w: client id MUST be 1", psatoken.ErrWrongSyntax)
	}

	clientID := v
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

func (c *ClaimsV2) SetTBBRoTPK(vals TBBRoTPKItems) error {
	if len(vals) == 0 {
		return fmt.Errorf("%w: TBB RoTPK: should not set empty value", psatoken.ErrWrongSyntax)
	}

	copiedVals, err := vals.Copy()
	if err != nil {
		return err
	}
	c.TBBRoTPK = &copiedVals

	return nil
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
	if *c.ClientID != 1 {
		return 0, fmt.Errorf("%w: client id MUST be 1", psatoken.ErrWrongSyntax)
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

// Returns a shallow copy of the TBBRoTPKItems slice.
func (c *ClaimsV2) GetTBBRoTPK() (TBBRoTPKItems, error) {
	if c.TBBRoTPK == nil || c.TBBRoTPK.IsEmpty() {
		return nil, psatoken.ErrOptionalClaimMissing
	}

	return c.TBBRoTPK.Copy()
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
