package realm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/veraison/psatoken"
)

const (
	MaxLenRealmExtendedMeas = 4
)

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

func ValidateRealmPubKey(b []byte) error {
	// Realm Public Key is ECC Public key of type ECC-P384 of size 97 bytes
	l := len(b)

	if l != 97 {
		return fmt.Errorf(
			"%w: length %d (realm public key MUST be 97 bytes)",
			psatoken.ErrWrongSyntax, l,
		)
	}

	if _, err := ecdsaPublicKeyFromRaw(b); err != nil {
		return fmt.Errorf(
			"%w: checking raw public key coordinates are on curve P-384: %v",
			psatoken.ErrWrongSyntax, err,
		)
	}

	return nil
}

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

func ValidateHashAlgID(v string) error {
	if v == "" {
		return fmt.Errorf("%w: empty string", psatoken.ErrWrongSyntax)
	}

	return nil
}

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

func ecdsaPublicKeyFromRaw(data []byte) (*ecdsa.PublicKey, error) {
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
