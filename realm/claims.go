// CCA Realm Claims
package realm

import (
	"encoding/json"
	"fmt"

	"github.com/veraison/eat"
)

type Claims struct {
	Challenge              *eat.Nonce `cbor:"10,keyasint" json:"cca-realm-challenge"`
	PersonalizationValue   *[]byte    `cbor:"44235,keyasint" json:"cca-realm-personalization-value"`
	InitialMeasurement     *[]byte    `cbor:"44238,keyasint" json:"cca-realm-initial-measurement"`
	ExtensibleMeasurements *[][]byte  `cbor:"44239,keyasint" json:"cca-realm-extensible-measurements"`
	HashAlgID              *string    `cbor:"44236,keyasint" json:"cca-realm-hash-algo-id"`
	PublicKey              *[]byte    `cbor:"44237,keyasint" json:"cca-realm-public-key"`
	PublicKeyHashAlgID     *string    `cbor:"44240,keyasint" json:"cca-realm-public-key-hash-algo-id"`
}

// Setters

func (c *Claims) SetChallenge(v []byte) error {
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

func (c *Claims) SetPersonalizationValue(v []byte) error {
	if err := isValidPersonalizationValue(v); err != nil {
		return err
	}

	c.PersonalizationValue = &v
	return nil
}

func (c *Claims) SetInitialMeasurement(v []byte) error {
	if err := isValidRealmMeas(v); err != nil {
		return err
	}

	c.InitialMeasurement = &v
	return nil
}

func (c *Claims) SetExtensibleMeasurements(v [][]byte) error {
	if err := isValidExtensibleMeas(v); err != nil {
		return err
	}

	c.ExtensibleMeasurements = &v
	return nil
}

func (c *Claims) SetHashAlgID(v string) error {
	if err := isValidHashAlgID(v); err != nil {
		return err
	}

	c.HashAlgID = &v
	return nil
}

func (c *Claims) SetPubKey(v []byte) error {
	if err := isValidRealmPubKey(v); err != nil {
		return err
	}

	c.PublicKey = &v
	return nil
}

func (c *Claims) SetPubKeyHashAlgID(v string) error {
	if v == "" {
		return fmt.Errorf("invalid null string set for cca-realm-pubkey-hash-algo-id")
	}

	c.PublicKeyHashAlgID = &v
	return nil
}

// Getters
func (c Claims) GetChallenge() ([]byte, error) {
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

func (c Claims) GetPersonalizationValue() ([]byte, error) {
	v := c.PersonalizationValue

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}
	if err := isValidPersonalizationValue(*v); err != nil {
		return nil, err
	}
	return *v, nil
}

func (c Claims) GetInitialMeasurement() ([]byte, error) {

	v := c.InitialMeasurement
	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}
	if err := isValidRealmMeas(*v); err != nil {
		return nil, err
	}
	return *v, nil
}

func (c Claims) GetExtensibleMeasurements() ([][]byte, error) {
	v := c.ExtensibleMeasurements
	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}
	if err := isValidExtensibleMeas(*v); err != nil {
		return nil, err
	}
	return *v, nil
}

func (c Claims) GetHashAlgID() (string, error) {
	v := c.HashAlgID
	if v == nil {
		return "", ErrMandatoryClaimMissing
	}
	if err := isValidHashAlgID(*v); err != nil {
		return "", err
	}
	return *v, nil
}

func (c Claims) GetPubKey() ([]byte, error) {
	v := c.PublicKey

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := isValidRealmPubKey(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c Claims) GetPubKeyHashAlgID() (string, error) {
	v := c.PublicKeyHashAlgID

	if v == nil {
		return "", ErrMandatoryClaimMissing
	}
	return *v, nil
}

// Semantic validation
func (c Claims) Validate() error {
	return validate(&c)
}

// Codecs

func (c *Claims) FromCBOR(buf []byte) error {
	err := c.FromUnvalidatedCBOR(buf)
	if err != nil {
		return err
	}

	err = c.Validate()
	if err != nil {
		return fmt.Errorf("validation of CCA realm claims failed: %w", err)
	}

	return nil
}

func (c *Claims) FromUnvalidatedCBOR(buf []byte) error {
	err := dm.Unmarshal(buf, c)
	if err != nil {
		return fmt.Errorf("CBOR decoding of CCA realm claims failed: %w", err)
	}

	return nil
}

func (c Claims) ToCBOR() ([]byte, error) {
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation of CCA realm claims failed: %w", err)
	}

	return c.ToUnvalidatedCBOR()
}

func (c Claims) ToUnvalidatedCBOR() ([]byte, error) {
	buf, err := em.Marshal(&c)
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding of CCA realm claims failed: %w", err)
	}

	return buf, nil
}

func (c *Claims) FromJSON(buf []byte) error {
	err := c.FromUnvalidatedJSON(buf)
	if err != nil {
		return err
	}

	err = c.Validate()
	if err != nil {
		return fmt.Errorf("validation of CCA realm claims failed: %w", err)
	}

	return nil
}

func (c *Claims) FromUnvalidatedJSON(buf []byte) error {
	err := json.Unmarshal(buf, c)
	if err != nil {
		return fmt.Errorf("JSON decoding of CCA realm claims failed: %w", err)
	}

	return nil
}

func (c Claims) ToJSON() ([]byte, error) {
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation of CCA realm claims failed: %w", err)
	}

	return c.ToUnvalidatedJSON()
}

func (c Claims) ToUnvalidatedJSON() ([]byte, error) {
	buf, err := json.Marshal(&c)
	if err != nil {
		return nil, fmt.Errorf("JSON encoding of CCA realm claims failed: %w", err)
	}

	return buf, nil
}
