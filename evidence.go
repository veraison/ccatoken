package ccatoken

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	cose "github.com/veraison/go-cose"
	ptoken "github.com/veraison/psatoken"
)

// claimType to hold the value of claim

type claimType int

const (
	PlatformClaim claimType = iota + 1
	RealmClaim
)

type CcaToken struct {
	CcaPlatformToken *[]byte `cbor:"44234,keyasint" json:"cca-platform-token"`
	CcaRealmToken    *[]byte `cbor:"44241,keyasint" json:"cca-realm-delegated-token"`
}

// CcaEvidence is a wrapper around CcaToken
type CcaEvidence struct {
	CcaPlatformClaims ptoken.IClaims
	CcaRealmClaims    IClaims
	message           *CcaToken
}

func (e *CcaEvidence) SetCcaPlatformClaims(c ptoken.IClaims) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("validation of cca-platform-claims failed: %w", err)
	}

	e.CcaPlatformClaims = c

	return nil
}

func (e *CcaEvidence) SetCcaRealmClaims(c IClaims) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("validation of cca-realm-claims failed: %w", err)
	}

	e.CcaRealmClaims = c
	return nil
}

// Sign signs the given evidence using the supplied Platform and Realm Signer
// and returns the complete CCA Evidence collection token as CBOR bytes

func (e *CcaEvidence) Sign(pSigner cose.Signer, rSigner cose.Signer) ([]byte, error) {

	if e.CcaPlatformClaims == nil {
		return nil, fmt.Errorf("missing platform claims in evidence")
	}

	if e.CcaRealmClaims == nil {
		return nil, fmt.Errorf("missing realm claims in evidence")
	}

	if err := e.signClaim(PlatformClaim, pSigner); err != nil {
		return nil, err
	}

	if err := e.signClaim(RealmClaim, rSigner); err != nil {
		return nil, err
	}

	// We do now have CcaPlatform and Realm Token setup correctly.
	buf, err := em.Marshal(e.message)
	if err != nil {
		return nil, fmt.Errorf("cbor encoding of CCA token failed: %w", err)
	}

	return buf, nil
}

func (e *CcaEvidence) signClaim(cl claimType, signer cose.Signer) error {
	var err error

	message := cose.NewSign1Message()
	if cl == PlatformClaim {
		message.Payload, err = e.CcaPlatformClaims.ToCBOR()
		if err != nil {
			return err
		}
	} else if cl == RealmClaim {
		message.Payload, err = e.CcaRealmClaims.ToCBOR()
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("invalid claimType %d: for signing", cl)
	}

	alg := signer.Algorithm()

	if strings.Contains(alg.String(), "unknown algorithm value") {
		return errors.New("signer has no algorithm")
	}

	message.Headers.Protected.SetAlgorithm(alg)

	err = message.Sign(rand.Reader, []byte(""), signer)
	if err != nil {
		return err
	}

	wrap, err := message.MarshalCBOR()
	if err != nil {
		return fmt.Errorf("unable to MarshalCBOR %d claimType = %w", cl, err)
	}
	if e.message == nil {
		ccaToken := CcaToken{}
		e.message = &ccaToken
	}

	if cl == PlatformClaim {
		e.message.CcaPlatformToken = &wrap
	} else {
		e.message.CcaRealmToken = &wrap
	}
	return nil
}

// Semantic validation, of CCA token
func (e CcaEvidence) ValidateToken() error {

	// At this point we just check that the both the
	// Platform and Realm tokens are set correctly.
	if e.message.CcaPlatformToken == nil {
		return fmt.Errorf("cca platform token not set")
	}

	if e.message.CcaRealmToken == nil {
		return fmt.Errorf("cca realm token not set")
	}

	return nil
}

// FromCBOR extracts the message to get the Realm and PlatforToken CBOR bytes
// and then set the Platform and Realm claims after checking validity

func (e *CcaEvidence) FromCBOR(buf []byte) error {
	ccaToken := CcaToken{}
	e.message = &ccaToken

	err := dm.Unmarshal(buf, e.message)
	if err != nil {
		return fmt.Errorf("cbor decoding of CCA evidence failed: %w", err)
	}

	err = e.ValidateToken()
	if err != nil {
		return fmt.Errorf("validation of CCA evidence failed: %w", err)
	}

	// This will set the byte array for Cca Platform Token
	if err = e.decodeClaims(PlatformClaim); err != nil {
		return fmt.Errorf("unable to decode platform claims %w", err)
	}

	// This will set the byte array for Cca Realm Token
	if err = e.decodeClaims(RealmClaim); err != nil {
		return fmt.Errorf("unable to decode platform claims %w", err)
	}
	return nil
}

func (e *CcaEvidence) decodeClaims(cl claimType) error {
	// This will set the byte array for Cca Realm and Platform Token
	message := cose.NewSign1Message()

	if cl == PlatformClaim {
		if err := message.UnmarshalCBOR(*e.message.CcaPlatformToken); err != nil {
			return fmt.Errorf("failed CBOR decoding for CWT: %w", err)
		}

		pclaims, err := ptoken.DecodeClaims(message.Payload)
		if err != nil {
			return fmt.Errorf("failed CBOR decoding of CCA platform claims: %w", err)
		}
		e.CcaPlatformClaims = pclaims
	} else {
		if err := message.UnmarshalCBOR(*e.message.CcaRealmToken); err != nil {
			return fmt.Errorf("failed CBOR decoding for CWT: %w", err)
		}
		rclaims, err := DecodeClaims(message.Payload)
		if err != nil {
			return fmt.Errorf("failed CBOR decoding of CCA realm claim: %w", err)
		}
		e.CcaRealmClaims = rclaims
	}
	return nil
}

func (e *CcaEvidence) Verify(iak crypto.PublicKey, rpk crypto.PublicKey) error {
	if e.message == nil {
		return fmt.Errorf("no message found")
	}

	// Check CCA Platform Token
	if e.message.CcaPlatformToken == nil {
		return fmt.Errorf("missing CCA platform Token")
	}

	// First verify the platform token
	if err := e.verifyCoseToken(*e.message.CcaPlatformToken, iak); err != nil {
		return fmt.Errorf("unable to verify platform token: %w", err)
	}

	// Check CCA Realm Token
	if e.message.CcaRealmToken == nil {
		return fmt.Errorf("missing CCA realm Token")
	}

	// Next verify the realm token
	if err := e.verifyCoseToken(*e.message.CcaRealmToken, rpk); err != nil {
		return fmt.Errorf("unable to verify realm token: %w", err)
	}
	return nil
}

func (e *CcaEvidence) verifyCoseToken(token []byte, pk crypto.PublicKey) error {

	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(token); err != nil {
		return fmt.Errorf("failed CBOR decoding for CWT: %w", err)
	}

	protected := message.Headers.Protected
	algo, err := protected.Algorithm()
	if err != nil {
		return fmt.Errorf("unable to get verification algorithm: %w", err)
	}

	verifier, err := cose.NewVerifier(algo, pk)
	if err != nil {
		return fmt.Errorf("unable to instantiate verifier: %w", err)
	}

	err = message.Verify([]byte(""), verifier)
	if err != nil {
		return err
	}

	return nil
}

// GetInstanceID returns the InstanceID claim from Platform claims that is to be used to locate the
// verification key or a nil pointer if no suitable InstanceID could be located.
// A call to this function on CcaEvidence that has not been successfully claims validated
// is meaningless.
func (e *CcaEvidence) GetInstanceID() *[]byte {
	instID, err := e.CcaPlatformClaims.GetInstID()
	if err != nil {
		return nil
	}
	return &instID
}

// GetRealmPublicKey returns the Public Key claim from Realm claims
// Realm Public Key is used to verify the signature on the Realm Token
// A call to this function on CcaEvidence that has not been successfully claims validated
// is meaningless.
func (e *CcaEvidence) GetRealmPublicKey() *[]byte {
	pubKey, err := e.CcaRealmClaims.GetPubKey()
	if err != nil {
		return nil
	}
	return &pubKey
}
