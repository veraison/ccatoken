package realm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
)

const (
	MaxLenRealmExtendedMeas = 4
)

func isCcaHashType(b []byte) error {
	l := len(b)

	if l != 64 {
		return fmt.Errorf(
			"%w: length %d (cca-hash-type MUST be 64 bytes)",
			ErrWrongClaimSyntax, l,
		)
	}

	return nil
}

func isValidChallenge(v []byte) error {
	if err := isCcaHashType(v); err != nil {
		return err
	}

	return nil
}

func isValidPersonalizationValue(b []byte) error {
	l := len(b)

	if l != 64 {
		return fmt.Errorf(
			"%w: length %d (cca-personalization-value MUST be 64 bytes)",
			ErrWrongClaimSyntax, l,
		)
	}
	return nil
}

func isValidRealmPubKey(b []byte) error {
	// Realm Public Key is ECC Public key of type ECC-P384 of size 97 bytes
	l := len(b)
	if l != 97 {
		return fmt.Errorf(
			"%w: length %d (cca-realm-public-key MUST be 97 bytes)",
			ErrWrongClaimSyntax, l,
		)
	}

	if _, err := ecdsaPublicKeyFromRaw(b); err != nil {
		return fmt.Errorf(
			"%w: checking raw public key coordinates are on curve P-384: %v",
			ErrWrongClaimSyntax, err,
		)
	}

	return nil
}
func isValidRealmMeas(b []byte) error {
	l := len(b)

	if l != 32 && l != 48 && l != 64 {
		return fmt.Errorf(
			"%w: length %d (cca-realm-measurement MUST be 32, 48 or 64 bytes)",
			ErrWrongClaimSyntax, l,
		)
	}
	return nil
}

func isValidHashAlgID(v string) error {
	if v == "" {
		return fmt.Errorf("%w: empty string", ErrWrongClaimSyntax)
	}
	return nil
}

func isValidExtensibleMeas(v [][]byte) error {
	if len(v) == 0 {
		return fmt.Errorf("%w cca-realm-extended-measurements", ErrMandatoryClaimMissing)
	}
	for i, meas := range v {
		if err := isValidRealmMeas(meas); err != nil {
			return fmt.Errorf("incorrect cca-realm-extended-measurement at index %d: %w", i, err)
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
