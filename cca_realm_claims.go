// CCA Realm Claims
package ccatoken

import (
	"encoding/json"
	"fmt"

	"github.com/veraison/eat"
)

type CcaRealmClaims struct {
	Challenge              *eat.Nonce `cbor:"10,keyasint" json:"cca-realm-challenge"`
	PersonalizationValue   *[]byte    `cbor:"44235,keyasint" json:"cca-realm-personalization-value"`
	InitialMeasurements    *[]byte    `cbor:"44238,keyasint" json:"cca-realm-initial-measurement"`
	ExtensibleMeasurements *[][]byte  `cbor:"44239,keyasint" json:"cca-realm-extensible-measurements"`
	HashAlgID              *string    `cbor:"44236,keyasint" json:"cca-realm-hash-algo-id"`
	PublicKey              *[]byte    `cbor:"44237,keyasint" json:"cca-realm-public-key"`
	PublickeyHashAlgID     *string    `cbor:"44240,keyasint" json:"cca-realm-public-key-hash-algo-id"`
}

// Setters

func (c *CcaRealmClaims) SetChallenge(v []byte) error {
	if err := isValidChallenge(v); err != nil {
		return err
	}

	n := eat.Nonce{}
	if err := n.Add(v); err != nil {
		return err
	}

	c.Challenge = &n
	return nil
}

func (c *CcaRealmClaims) SetPersonalizationValue(v []byte) error {
	if err := isValidPersonalizationValue(v); err != nil {
		return err
	}

	c.PersonalizationValue = &v
	return nil
}

func (c *CcaRealmClaims) SetInitialMeasurements(v []byte) error {
	if err := isValidRealmMeas(v); err != nil {
		return err
	}

	c.InitialMeasurements = &v
	return nil
}

func (c *CcaRealmClaims) SetExtensibleMeasurements(v [][]byte) error {
	if err := isValidExtensibleMeas(v); err != nil {
		return err
	}

	c.ExtensibleMeasurements = &v
	return nil
}

func (c *CcaRealmClaims) SetHashAlgID(v string) error {
	if err := isValidHashAlgID(v); err != nil {
		return err
	}

	c.HashAlgID = &v
	return nil
}

func (c *CcaRealmClaims) SetPubKey(v []byte) error {
	if err := isValidRealmPubKey(v); err != nil {
		return err
	}

	c.PublicKey = &v
	return nil
}

func (c *CcaRealmClaims) SetPubKeyHashAlgID(v string) error {
	if v == "" {
		return fmt.Errorf("invalid null string set for cca-realm-pubkey-hash-alg-id")
	}

	c.PublickeyHashAlgID = &v
	return nil
}

// Getters
func (c CcaRealmClaims) GetChallenge() ([]byte, error) {
	v := c.Challenge

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	l := v.Len()

	if l != 1 {
		return nil, fmt.Errorf("%w: got %d nonces, want 1", ErrWrongClaimSyntax, l)
	}

	n := v.GetI(0)
	if err := isValidChallenge(n); err != nil {
		return nil, err
	}
	return n, nil
}

func (c CcaRealmClaims) GetPersonalizationValue() ([]byte, error) {
	v := c.PersonalizationValue

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}
	if err := isValidPersonalizationValue(*v); err != nil {
		return nil, err
	}
	return *v, nil
}

func (c CcaRealmClaims) GetInitialMeasurements() ([]byte, error) {

	v := c.InitialMeasurements
	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}
	if err := isValidRealmMeas(*v); err != nil {
		return nil, err
	}
	return *v, nil
}

func (c CcaRealmClaims) GetExtensibleMeasurements() ([][]byte, error) {
	v := c.ExtensibleMeasurements
	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}
	if err := isValidExtensibleMeas(*v); err != nil {
		return nil, err
	}
	return *v, nil
}

func (c CcaRealmClaims) GetHashAlgID() (string, error) {
	v := c.HashAlgID
	if v == nil {
		return "", ErrMandatoryClaimMissing
	}
	if err := isValidHashAlgID(*v); err != nil {
		return "", err
	}
	return *v, nil
}

func (c CcaRealmClaims) GetPubKey() ([]byte, error) {
	v := c.PublicKey

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := isValidRealmPubKey(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c CcaRealmClaims) GetPubKeyHashAlgID() (string, error) {
	v := c.PublickeyHashAlgID

	if v == nil {
		return "", ErrMandatoryClaimMissing
	}
	return *v, nil
}

// Semantic validation
func (c CcaRealmClaims) Validate() error {
	return validate(&c)
}

// Codecs

func (c *CcaRealmClaims) FromCBOR(buf []byte) error {
	err := dm.Unmarshal(buf, c)
	if err != nil {
		return fmt.Errorf("CBOR decoding of CCA realm claims failed: %w", err)
	}

	err = c.Validate()
	if err != nil {
		return fmt.Errorf("validation of CCA realm claims failed: %w", err)
	}

	return nil
}

func (c CcaRealmClaims) ToCBOR() ([]byte, error) {
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation of CCA realm claims failed: %w", err)
	}

	buf, err := em.Marshal(&c)
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding of CCA realm claims failed: %w", err)
	}

	return buf, nil
}

func (c *CcaRealmClaims) FromJSON(buf []byte) error {
	err := json.Unmarshal(buf, c)
	if err != nil {
		return fmt.Errorf("JSON decoding of CCA realm claims failed: %w", err)
	}

	err = c.Validate()
	if err != nil {
		return fmt.Errorf("validation of CCA realm claims failed: %w", err)
	}

	return nil
}

func (c CcaRealmClaims) ToJSON() ([]byte, error) {
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation of CCA realm claims failed: %w", err)
	}

	buf, err := json.Marshal(&c)
	if err != nil {
		return nil, fmt.Errorf("JSON encoding of CCA realm claims failed: %w", err)
	}

	return buf, nil
}