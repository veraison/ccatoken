// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"encoding/json"
	"fmt"

	"github.com/veraison/eat"
	"github.com/veraison/psatoken"
)

const LegacyProfileName = "http://arm.com/CCA-SSD/1.0.0"
const ProfileName = "tag:arm.com,2023:cca_platform#1.0.0"

// Profile is the psatoken.IProfile implementation for CCA claims. It is
// registered to associate the claims with the profile name, so that it can be
// automatically used during unmarshaling.
type Profile struct{}

func (o Profile) GetName() string {
	return ProfileName
}

func (o Profile) GetClaims() psatoken.IClaims {
	return NewClaims()
}

type LegacyProfile struct{}

func (o LegacyProfile) GetName() string {
	return LegacyProfileName
}

func (o LegacyProfile) GetClaims() psatoken.IClaims {
	return NewLegacyClaims()
}

// Claims contains the CCA platform claims. It implements IClaims, which is an
// extension of psatoken.IClaims.
type Claims struct {
	Profile           *eat.Profile           `cbor:"265,keyasint" json:"cca-platform-profile"`
	Challenge         *eat.Nonce             `cbor:"10,keyasint" json:"cca-platform-challenge"`
	ImplID            *[]byte                `cbor:"2396,keyasint" json:"cca-platform-implementation-id"`
	InstID            *eat.UEID              `cbor:"256,keyasint" json:"cca-platform-instance-id"`
	Config            *[]byte                `cbor:"2401,keyasint" json:"cca-platform-config"`
	SecurityLifeCycle *uint16                `cbor:"2395,keyasint" json:"cca-platform-lifecycle"`
	SwComponents      psatoken.ISwComponents `cbor:"2399,keyasint" json:"cca-platform-sw-components"`

	VSI       *string `cbor:"2400,keyasint,omitempty" json:"cca-platform-service-indicator,omitempty"`
	HashAlgID *string `cbor:"2402,keyasint" json:"cca-platform-hash-algo-id"`

	CanonicalProfile string `cbor:"-" json:"-"`
}

// NewClaims claims returns a new instance of Claims.
func NewClaims() IClaims {
	return newClaims(ProfileName)
}

func NewLegacyClaims() IClaims {
	return newClaims(LegacyProfileName)
}

func newClaims(profileName string) IClaims {
	p := eat.Profile{}
	if err := p.Set(profileName); err != nil {
		// should never get here as using known good constant as input
		panic(err)
	}

	return &Claims{
		Profile:          &p,
		SwComponents:     &psatoken.SwComponents[*psatoken.SwComponent]{},
		CanonicalProfile: profileName,
	}
}

// Semantic validation
func (c *Claims) Validate() error {
	return ValidateClaims(c)
}

// Codecs

// this type alias is used to prevent infinite recursion during marshaling.
type claims Claims

// MarshalCBOR encodes the claims into CBOR
func (c *Claims) UnmarshalCBOR(buf []byte) error {
	c.Profile = nil // clear profile to make sure we taked it from buf

	return dm.Unmarshal(buf, (*claims)(c))
}

// UnmarshalCBOR decodes the claims from CBOR
func (c Claims) MarshalCBOR() ([]byte, error) {
	if c.SwComponents != nil && c.SwComponents.IsEmpty() {
		c.SwComponents = nil
	}

	return em.Marshal((*claims)(&c))
}

// UnmarshalJSON decodes the claims from JSON
func (c *Claims) UnmarshalJSON(buf []byte) error {
	c.Profile = nil // clear profile to make sure we taked it from buf

	return json.Unmarshal(buf, (*claims)(c))
}

// MarshalJSON encodes the claims into JSON
func (c Claims) MarsahlJSON() ([]byte, error) {
	if c.SwComponents != nil && c.SwComponents.IsEmpty() {
		c.SwComponents = nil
	}

	return json.Marshal((*claims)(&c))
}

func (c *Claims) SetImplID(v []byte) error {
	if err := psatoken.ValidateImplID(v); err != nil {
		return err
	}

	c.ImplID = &v

	return nil
}

func (c *Claims) SetNonce(v []byte) error {
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

func (c *Claims) SetInstID(v []byte) error {
	if err := psatoken.ValidateInstID(v); err != nil {
		return err
	}

	ueid := eat.UEID(v)

	c.InstID = &ueid

	return nil
}

func (c *Claims) SetVSI(v string) error {
	if err := psatoken.ValidateVSI(v); err != nil {
		return err
	}

	c.VSI = &v

	return nil
}

func (c *Claims) SetSecurityLifeCycle(v uint16) error {
	if err := ValidateSecurityLifeCycle(v); err != nil {
		return err
	}

	c.SecurityLifeCycle = &v

	return nil
}

func (c *Claims) SetBootSeed(v []byte) error {
	return fmt.Errorf("%w: boot seed", psatoken.ErrClaimNotInProfile)
}

func (c *Claims) SetCertificationReference(v string) error {
	return fmt.Errorf("%w: certification reference", psatoken.ErrClaimNotInProfile)
}

func (c *Claims) SetClientID(int32) error {
	return fmt.Errorf("%w: client id", psatoken.ErrClaimNotInProfile)
}

func (c *Claims) SetSoftwareComponents(scs []psatoken.ISwComponent) error {
	if c.SwComponents == nil {
		c.SwComponents = &psatoken.SwComponents[*psatoken.SwComponent]{}
	}

	return c.SwComponents.Replace(scs)
}

func (c *Claims) SetConfig(v []byte) error {
	if len(v) == 0 {
		return psatoken.ErrMandatoryClaimMissing
	}

	c.Config = &v

	return nil
}

func (c *Claims) SetHashAlgID(v string) error {
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
func (c *Claims) GetProfile() (string, error) {
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

func (c *Claims) GetClientID() (int32, error) {
	return -1, fmt.Errorf("%w: client id", psatoken.ErrClaimNotInProfile)
}

func (c *Claims) GetSecurityLifeCycle() (uint16, error) {
	if c.SecurityLifeCycle == nil {
		return 0, psatoken.ErrMandatoryClaimMissing
	}

	if err := psatoken.ValidateSecurityLifeCycle(*c.SecurityLifeCycle); err != nil {
		return 0, err
	}

	return *c.SecurityLifeCycle, nil
}

func (c *Claims) GetImplID() ([]byte, error) {
	if c.ImplID == nil {
		return nil, psatoken.ErrMandatoryClaimMissing
	}

	if err := psatoken.ValidateImplID(*c.ImplID); err != nil {
		return nil, err
	}

	return *c.ImplID, nil
}

func (c *Claims) GetBootSeed() ([]byte, error) {
	return nil, fmt.Errorf("%w: boot seed", psatoken.ErrClaimNotInProfile)
}

func (c *Claims) GetCertificationReference() (string, error) {
	return "", fmt.Errorf("%w: certification reference", psatoken.ErrClaimNotInProfile)
}

func (c *Claims) GetSoftwareComponents() ([]psatoken.ISwComponent, error) {
	if c.SwComponents == nil || c.SwComponents.IsEmpty() {
		return nil, fmt.Errorf("%w (MUST have at least one sw component)",
			psatoken.ErrMandatoryClaimMissing)
	}

	return c.SwComponents.Values()
}

func (c *Claims) GetNonce() ([]byte, error) {
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

func (c *Claims) GetInstID() ([]byte, error) {
	v := c.InstID

	if v == nil {
		return nil, psatoken.ErrMandatoryClaimMissing
	}

	if err := psatoken.ValidateInstID(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c *Claims) GetVSI() (string, error) {
	if c.VSI == nil {
		return "", psatoken.ErrOptionalClaimMissing
	}

	if err := psatoken.ValidateVSI(*c.VSI); err != nil {
		return "", err
	}

	return *c.VSI, nil
}

func (c *Claims) GetConfig() ([]byte, error) {
	v := c.Config
	if v == nil {
		return nil, psatoken.ErrMandatoryClaimMissing
	}
	return *v, nil
}

func (c *Claims) GetHashAlgID() (string, error) {
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
	if err := psatoken.RegisterProfile(Profile{}); err != nil {
		panic(err)
	}

	if err := psatoken.RegisterProfile(LegacyProfile{}); err != nil {
		panic(err)
	}
}
