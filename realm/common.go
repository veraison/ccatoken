package realm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	cose "github.com/veraison/go-cose"

	"github.com/veraison/psatoken"
)

const (
	MaxLenRealmExtendedMeas = 4
)

// ValidateChallenge returns an error if the provided value does not contain a
// valid CCA challenge.
func ValidateChallenge(v []byte) error {
	l := len(v)

	if l != 64 {
		return fmt.Errorf(
			"%w: length %d (hash MUST be 64 bytes)",
			psatoken.ErrWrongSyntax, l,
		)
	}

	return nil
}

// ValidatePersonalizationValue returns an error if the provided value is not a
// valid personalization value (must be exactly 64 bytes long).
func ValidatePersonalizationValue(b []byte) error {
	l := len(b)

	if l != 64 {
		return fmt.Errorf(
			"%w: length %d (personalization value MUST be 64 bytes)",
			psatoken.ErrWrongSyntax, l,
		)
	}
	return nil
}

// ValidateRealmPubKey returns an error if the provided value does not contain
// a valid realm public key (must 97-byte ECC-P384).
func ValidateRealmPubKey(b []byte) error {
	l := len(b)

	if l != 97 {
		return fmt.Errorf(
			"%w: length %d (realm public key MUST be 97 bytes)",
			psatoken.ErrWrongSyntax, l,
		)
	}

	if _, err := ECDSAPublicKeyFromRaw(b); err != nil {
		return fmt.Errorf(
			"%w: checking raw public key coordinates are on curve P-384: %v",
			psatoken.ErrWrongSyntax, err,
		)
	}

	return nil
}

// ValidateRealmPubKeyCOSE returns an error if the provided value does not
// contain a valid realm public key in CBOR-encoded COSE_Key format
func ValidateRealmPubKeyCOSE(b []byte) error {
	var k cose.Key

	if err := k.UnmarshalCBOR(b); err != nil {
		return fmt.Errorf(
			"%w: checking realm public key is a CBOR-encoded COSE_Key: %v",
			psatoken.ErrWrongSyntax, err,
		)
	}

	if k.Type != cose.KeyTypeEC2 {
		return fmt.Errorf("%w: realm public key is not EC2", psatoken.ErrWrongSyntax)
	}

	return nil
}

// ValidateRealmMeas returns an error if the provided value does not contain a
// valid realm measurement (must be 32, 48, or 64 bytes long).
func ValidateRealmMeas(b []byte) error {
	l := len(b)

	if l != 32 && l != 48 && l != 64 {
		return fmt.Errorf(
			"%w: length %d (realm measurement MUST be 32, 48 or 64 bytes)",
			psatoken.ErrWrongSyntax, l,
		)
	}

	return nil
}

// ValidateHashAlgID returns an error if the provided value is not a valid
// hash algorithm string.
func ValidateHashAlgID(v string) error {
	if v == "" {
		return fmt.Errorf("%w: empty string", psatoken.ErrWrongSyntax)
	}

	return nil
}

// ValidateExtendedMeas returns an error if the provided slice does not contain
// valid realm extended measurements (it must be non-empty, and each value must
// be a valid ream measurement).
func ValidateExtendedMeas(v [][]byte) error {
	if len(v) == 0 {
		return fmt.Errorf("%w realm extended measurements",
			psatoken.ErrMandatoryClaimMissing)
	}

	for i, meas := range v {
		if err := ValidateRealmMeas(meas); err != nil {
			return fmt.Errorf("incorrect realm extended measurement at index %d: %w", i, err)
		}
	}

	return nil
}

func ECDSAPublicKeyFromRaw(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P384(), data) // nolint:staticcheck
	if x == nil {
		return nil, errors.New("failed to unmarshal elliptic curve point")
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     x,
		Y:     y,
	}, nil
}

func ECDSAPublicKeyFromCOSEKey(buf []byte) (*ecdsa.PublicKey, error) {
	var k cose.Key

	if err := k.UnmarshalCBOR(buf); err != nil {
		return nil, err
	}

	if k.Type != cose.KeyTypeEC2 {
		return nil, errors.New("key type is not EC2")
	}

	pk, err := k.PublicKey()
	if err != nil {
		return nil, err
	}

	epk, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		// Paranoid check: this should not happen since k has been already
		// checked to be a valid EC2 key.
		return nil, errors.New("key cannot be converted to public ECDSA")
	}

	return epk, nil
}
