// CCA Realm Claims
package realm

import (
	"fmt"

	"github.com/veraison/eat"
	"github.com/veraison/psatoken"
)

const ProfileName = "tag:arm.com,2023:realm#1.0.0"

// Claims contains the CCA realm claims. It implements IClaims, which is an
// extension of psatoken.IClaimBase.
type Claims struct {
	Profile                *eat.Profile `cbor:"265,keyasint" json:"cca-realm-profile,omitempty"`
	Challenge              *eat.Nonce   `cbor:"10,keyasint" json:"cca-realm-challenge"`
	PersonalizationValue   *[]byte      `cbor:"44235,keyasint" json:"cca-realm-personalization-value"`
	InitialMeasurement     *[]byte      `cbor:"44238,keyasint" json:"cca-realm-initial-measurement"`
	ExtensibleMeasurements *[][]byte    `cbor:"44239,keyasint" json:"cca-realm-extensible-measurements"`
	HashAlgID              *string      `cbor:"44236,keyasint" json:"cca-realm-hash-algo-id"`
	PublicKey              *[]byte      `cbor:"44237,keyasint" json:"cca-realm-public-key"`
	PublicKeyHashAlgID     *string      `cbor:"44240,keyasint" json:"cca-realm-public-key-hash-algo-id"`
}

// NewClaims claims returns a new instance of Claims.
func NewClaims() IClaims {
	p := eat.Profile{}
	if err := p.Set(ProfileName); err != nil {
		// should never get here as using known good constant as input
		panic(err)
	}

	return &Claims{Profile: &p}
}

func newClaimsForDecoding() IClaims {
	return &Claims{}
}

// Setters

func (c *Claims) SetChallenge(v []byte) error {
	if err := ValidateChallenge(v); err != nil {
		return err
	}

	n := eat.Nonce{}
	if err := n.Add(v); err != nil {
		return err
	}

	c.Challenge = &n
	return nil
}

func (c *Claims) SetPersonalizationValue(v []byte) error {
	if err := ValidatePersonalizationValue(v); err != nil {
		return err
	}

	c.PersonalizationValue = &v
	return nil
}

func (c *Claims) SetInitialMeasurement(v []byte) error {
	if err := ValidateRealmMeas(v); err != nil {
		return err
	}

	c.InitialMeasurement = &v
	return nil
}

func (c *Claims) SetExtensibleMeasurements(v [][]byte) error {
	if err := ValidateExtendedMeas(v); err != nil {
		return err
	}

	c.ExtensibleMeasurements = &v
	return nil
}

func (c *Claims) SetHashAlgID(v string) error {
	if err := ValidateHashAlgID(v); err != nil {
		return err
	}

	c.HashAlgID = &v
	return nil
}

func (c *Claims) SetPubKey(v []byte) error {
	if c.Profile == nil {
		if err := ValidateRealmPubKey(v); err != nil {
			return err
		}
	} else {
		if err := ValidateRealmPubKeyCOSE(v); err != nil {
			return err
		}
	}

	c.PublicKey = &v
	return nil
}

func (c *Claims) SetPubKeyHashAlgID(v string) error {
	if v == "" {
		return fmt.Errorf("invalid null string set for realm pubkey hash alg ID")
	}

	c.PublicKeyHashAlgID = &v
	return nil
}

// Getters
func (c Claims) GetChallenge() ([]byte, error) {
	v := c.Challenge
	if v == nil {
		return nil, psatoken.ErrMandatoryClaimMissing
	}

	l := v.Len()
	if l != 1 {
		return nil, fmt.Errorf("%w: got %d nonces, want 1", psatoken.ErrWrongSyntax, l)
	}

	n := v.GetI(0)
	if err := ValidateChallenge(n); err != nil {
		return nil, err
	}

	return n, nil
}

// If profile is not found return ErrOptionalClaimMissing
func (c *Claims) GetProfile() (string, error) {
	if c.Profile == nil {
		return "", psatoken.ErrOptionalClaimMissing
	}

	profileString, err := c.Profile.Get()
	if err != nil {
		return "", err
	}

	if profileString != ProfileName {
		return "", fmt.Errorf("%w: expecting %q, got %q",
			psatoken.ErrWrongProfile, ProfileName, profileString)
	}

	return c.Profile.Get()
}

func (c Claims) GetPersonalizationValue() ([]byte, error) {
	v := c.PersonalizationValue

	if v == nil {
		return nil, psatoken.ErrMandatoryClaimMissing
	}

	if err := ValidatePersonalizationValue(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c Claims) GetInitialMeasurement() ([]byte, error) {
	v := c.InitialMeasurement
	if v == nil {
		return nil, psatoken.ErrMandatoryClaimMissing
	}

	if err := ValidateRealmMeas(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c Claims) GetExtensibleMeasurements() ([][]byte, error) {
	v := c.ExtensibleMeasurements
	if v == nil {
		return nil, psatoken.ErrMandatoryClaimMissing
	}

	if err := ValidateExtendedMeas(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c Claims) GetHashAlgID() (string, error) {
	v := c.HashAlgID
	if v == nil {
		return "", psatoken.ErrMandatoryClaimMissing
	}
	if err := ValidateHashAlgID(*v); err != nil {
		return "", err
	}
	return *v, nil
}

func (c Claims) GetPubKey() ([]byte, error) {
	v := c.PublicKey

	if v == nil {
		return nil, psatoken.ErrMandatoryClaimMissing
	}

	if c.Profile == nil {
		if err := ValidateRealmPubKey(*v); err != nil {
			return nil, err
		}
	} else {
		if err := ValidateRealmPubKeyCOSE(*v); err != nil {
			return nil, err
		}
	}

	return *v, nil
}

func (c Claims) GetPubKeyHashAlgID() (string, error) {
	v := c.PublicKeyHashAlgID

	if v == nil {
		return "", psatoken.ErrMandatoryClaimMissing
	}

	return *v, nil
}

// Semantic validation
func (c Claims) Validate() error {
	return ValidateClaims(&c)
}
