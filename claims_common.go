package ccatoken

import "fmt"

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
	// In future things will change
	l := len(b)
	if l != 97 {
		return fmt.Errorf(
			"%w: length %d (cca-realm-public-key MUST be 97 bytes)",
			ErrWrongClaimSyntax, l,
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

	// It is recommended that IANA Hash Function Textual Names be used for setting HashAlgID
	switch v {
	case "md2", "md5", "sha-1", "sha-224", "sha-256", "sha-384", "sha-512", "shake128", "shake256":
		return nil
	}
	return fmt.Errorf("%w: wrong syntax", ErrWrongClaimSyntax)
}

func isValidExtensibleMeas(v [][]byte) error {
	if len(v) == 0 {
		return fmt.Errorf("%w cca-realm-extended-measurements:", ErrMandatoryClaimMissing)
	}
	for i, meas := range v {
		if err := isValidRealmMeas(meas); err != nil {
			return fmt.Errorf("incorrect cca-realm-extended-measurement at index %d: %w", i, err)
		}
	}
	return nil
}
