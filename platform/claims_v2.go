// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"encoding/json"
	"fmt"

	"github.com/veraison/eat"
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
	return NewClaims()
}

// Claims contains the CCA platform claims. It implements IClaims, which is an
// extension of psatoken.IClaims.
type ClaimsV2 struct {
	ClaimsV1
	ClientID            *uint8         `cbor:"2394,keyasint" json:"cca-platform-client-id"`
	ManufacturingConfig *[]byte        `cbor:"2403,keyasint,omitempty" json:"cca-platform-manufacturing-config,omitempty"`
	TBBRoTPK            *TBBRoTPKItems `cbor:"2405,keyasint,omitempty" json:"cca-platform-tbb-rotpk,omitempty"`
	PeerSigners         *[]byte        `cbor:"2406,keyasint,omitempty" json:"cca-platform-peer-signers,omitempty"`
	// Extension  *TODO		`cbor:"2404,keyasint,omitempty" json:"cca-platform-extension,omitempty"` // to find out the type
}

// NewClaims claims returns a new instance of Claims.
func NewClaimsV2() IClaims {
	p := eat.Profile{}
	if err := p.Set(ProfileNameV2); err != nil {
		// should never get here as using known good constant as input
		panic(err)
	}

	return &ClaimsV1{
		Profile:          &p,
		SwComponents:     &psatoken.SwComponents[*psatoken.SwComponent]{},
		CanonicalProfile: ProfileNameV2,
	}
}

// Semantic validation
func (c *ClaimsV2) Validate() error {
	return ValidateClaims(c)
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

	return json.Marshal((*claimsV2)(&c))
}

func (c *ClaimsV2) SetImplID(v []byte) error {
	if err := psatoken.ValidateImplID(v); err != nil {
		return err
	}

	c.ImplID = &v

	return nil
}

func (c *ClaimsV2) SetNonce(v []byte) error {
	if err := psatoken.ValidatePSAHashType(v); err != nil {
		return err
	}

	n := eat.Nonce{}

	if err := n.Add(v); err != nil {
		return err
	}

	c.Challenge = &n

	return nil
}

func (c *ClaimsV2) SetInstID(v []byte) error {
	if err := psatoken.ValidateInstID(v); err != nil {
		return err
	}

	ueid := eat.UEID(v)

	c.InstID = &ueid

	return nil
}

func (c *ClaimsV2) SetVSI(v string) error {
	if err := psatoken.ValidateVSI(v); err != nil {
		return err
	}

	c.VSI = &v

	return nil
}

func (c *ClaimsV2) SetSecurityLifeCycle(v uint16) error {
	if err := ValidateSecurityLifeCycle(v); err != nil {
		return err
	}

	c.SecurityLifeCycle = &v

	return nil
}

func (c *ClaimsV2) SetBootSeed(v []byte) error {
	return fmt.Errorf("%w: boot seed", psatoken.ErrClaimNotInProfile)
}

func (c *ClaimsV2) SetCertificationReference(v string) error {
	return fmt.Errorf("%w: certification reference", psatoken.ErrClaimNotInProfile)
}

func (c *ClaimsV2) SetClientID(int32) error {
	return fmt.Errorf("%w: client id", psatoken.ErrClaimNotInProfile)
}

func (c *ClaimsV2) SetSoftwareComponents(scs []psatoken.ISwComponent) error {
	if c.SwComponents == nil {
		c.SwComponents = &psatoken.SwComponents[*psatoken.SwComponent]{}
	}

	return c.SwComponents.Replace(scs)
}

func (c *ClaimsV2) SetConfig(v []byte) error {
	if len(v) == 0 {
		return psatoken.ErrMandatoryClaimMissing
	}

	c.Config = &v

	return nil
}

func (c *ClaimsV2) SetHashAlgID(v string) error {
	if err := psatoken.ValidateHashAlgID(v); err != nil {
		return err
	}

	c.HashAlgID = &v

	return nil
}

// Getters return a validated value or an error
// After successful call to Validate(), getters of mandatory claims are assured
// to never fail.  Getters of optional claim may still fail with
// ErrOptionalClaimMissing in case the claim is not present.
func (c *ClaimsV2) GetProfile() (string, error) {
	if c.Profile == nil {
		return "", psatoken.ErrMandatoryClaimMissing
	}

	profileString, err := c.Profile.Get()
	if err != nil {
		return "", err
	}

	if profileString != c.CanonicalProfile {
		return "", fmt.Errorf("%w: expecting %q, got %q",
			psatoken.ErrWrongProfile, c.CanonicalProfile, profileString)
	}

	return profileString, nil
}

func (c *ClaimsV2) GetClientID() (int32, error) {
	return -1, fmt.Errorf("%w: client id", psatoken.ErrClaimNotInProfile)
}

func (c *ClaimsV2) GetSecurityLifeCycle() (uint16, error) {
	if c.SecurityLifeCycle == nil {
		return 0, psatoken.ErrMandatoryClaimMissing
	}

	if err := psatoken.ValidateSecurityLifeCycle(*c.SecurityLifeCycle); err != nil {
		return 0, err
	}

	return *c.SecurityLifeCycle, nil
}

func (c *ClaimsV2) GetImplID() ([]byte, error) {
	if c.ImplID == nil {
		return nil, psatoken.ErrMandatoryClaimMissing
	}

	if err := psatoken.ValidateImplID(*c.ImplID); err != nil {
		return nil, err
	}

	return *c.ImplID, nil
}

func (c *ClaimsV2) GetBootSeed() ([]byte, error) {
	return nil, fmt.Errorf("%w: boot seed", psatoken.ErrClaimNotInProfile)
}

func (c *ClaimsV2) GetCertificationReference() (string, error) {
	return "", fmt.Errorf("%w: certification reference", psatoken.ErrClaimNotInProfile)
}

func (c *ClaimsV2) GetSoftwareComponents() ([]psatoken.ISwComponent, error) {
	if c.SwComponents == nil || c.SwComponents.IsEmpty() {
		return nil, fmt.Errorf("%w (MUST have at least one sw component)",
			psatoken.ErrMandatoryClaimMissing)
	}

	return c.SwComponents.Values()
}

func (c *ClaimsV2) GetNonce() ([]byte, error) {
	v := c.Challenge

	if v == nil {
		return nil, psatoken.ErrMandatoryClaimMissing
	}

	l := v.Len()

	if l != 1 {
		return nil, fmt.Errorf("%w: got %d nonces, want 1", psatoken.ErrWrongSyntax, l)
	}

	n := v.GetI(0)
	if err := psatoken.ValidateNonce(n); err != nil {
		return nil, err
	}

	return n, nil
}

func (c *ClaimsV2) GetInstID() ([]byte, error) {
	v := c.InstID

	if v == nil {
		return nil, psatoken.ErrMandatoryClaimMissing
	}

	if err := psatoken.ValidateInstID(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c *ClaimsV2) GetVSI() (string, error) {
	if c.VSI == nil {
		return "", psatoken.ErrOptionalClaimMissing
	}

	if err := psatoken.ValidateVSI(*c.VSI); err != nil {
		return "", err
	}

	return *c.VSI, nil
}

func (c *ClaimsV2) GetConfig() ([]byte, error) {
	v := c.Config
	if v == nil {
		return nil, psatoken.ErrMandatoryClaimMissing
	}
	return *v, nil
}

func (c *ClaimsV2) GetHashAlgID() (string, error) {
	v := c.HashAlgID

	if v == nil {
		return "", psatoken.ErrMandatoryClaimMissing
	}
	if err := psatoken.ValidateHashAlgID(*v); err != nil {
		return "", err
	}
	return *v, nil
}

func init() {
	if err := psatoken.RegisterProfile(ProfileV2{}); err != nil {
		panic(err)
	}
}
