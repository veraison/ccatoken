// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ccatoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"strings"

	cbortag "github.com/fxamacker/cbor/v2"

	"github.com/veraison/ccatoken/platform"
	"github.com/veraison/ccatoken/realm"
	cose "github.com/veraison/go-cose"
	"github.com/veraison/psatoken"

)

type CMWCollectionEntry struct {
	_        struct{} `cbor:",toarray"`
	Coaptype int
	TokenStr *[]byte
}

// CBORCMWCollection is a wrapper containing the CBOR data for both platform and
// realm tokens. This follows CMW format (draft-ietf-rats-msg-wrap)
type CBORCMWCollection struct {
	PlatformTokenColl CMWCollectionEntry `cbor:"44234,keyasint"`
	RealmTokenColl    CMWCollectionEntry `cbor:"44241,keyasint"`
}

// CBORCMWCollection is a wrapper containing the CBOR data for both platform and
// realm tokens using a deprecated Collection encoding. This form is included
// for transition purposes.
type CBORCollection struct {
	PlatformToken *[]byte `cbor:"44234,keyasint"`
	RealmToken    *[]byte `cbor:"44241,keyasint"`
}

// JSONCollection is a wrapper containing the JSON data for both platform and
// realm tokens.
type JSONCollection struct {
	PlatformToken json.RawMessage `json:"cca-platform-token,omitempty"`
	RealmToken    json.RawMessage `json:"cca-realm-delegated-token,omitempty"`
}

// DecodeAndValidateEvidenceFromCBOR unmarshals CCA claims collection from
// provided CBOR and validates both sets of claims.
func DecodeAndValidateEvidenceFromCBOR(buf []byte) (*Evidence, error) {
	ev, err := DecodeEvidenceFromCBOR(buf)
	if err != nil {
		return nil, err
	}

	if err := ev.Validate(); err != nil {
		return nil, err
	}

	return ev, nil
}

// DecodeEvidenceFromCBOR unmarshals CCA claims collection from provided CBOR.
func DecodeEvidenceFromCBOR(buf []byte) (*Evidence, error) {
	ev := &Evidence{}

	if err := ev.UnmarshalCBOR(buf); err != nil {
		return nil, err
	}

	return ev, nil
}

// DecodeAndValidateEvidenceFromJSON unmarshals CCA claims collection from
// provided JSON and validates both sets of claims.
func DecodeAndValidateEvidenceFromJSON(buf []byte) (*Evidence, error) {
	ev, err := DecodeEvidenceFromJSON(buf)
	if err != nil {
		return nil, err
	}

	if err := ev.Validate(); err != nil {
		return nil, err
	}

	return ev, nil
}

// DecodeEvidenceFromJSON unmarshals CCA claims collection from provided JSON.
func DecodeEvidenceFromJSON(buf []byte) (*Evidence, error) {
	ev := &Evidence{}

	if err := ev.UnmarshalJSON(buf); err != nil {
		return nil, err
	}

	return ev, nil
}

// ValidateAndEncodeEvidenceToJSON validates and then marshals CCA evidence
// to JSON.
func ValidateAndEncodeEvidenceToJSON(e *Evidence) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}

	return EncodeEvidenceToJSON(e)
}

// EncodeEvidenceToJSON marshals CCA evidence to JSON.
func EncodeEvidenceToJSON(e *Evidence) ([]byte, error) {
	return json.Marshal(e)
}

// Evidence is a wrapper around CcaToken
type Evidence struct {
	PlatformClaims platform.IClaims
	RealmClaims    realm.IClaims
	platformTokenRaw *[]byte
	realmTokenRaw *[]byte
}

// Validate that both platform and realm cliams have been set and are valid.
func (e *Evidence) Validate() error {
	if e.PlatformClaims == nil && e.RealmClaims == nil {
		return errors.New("claims not set in evidence")
	} else if e.PlatformClaims == nil {
		return errors.New("missing platform claims")
	} else if e.RealmClaims == nil {
		return errors.New("missing realm claims")
	}

	if err := e.PlatformClaims.Validate(); err != nil {
		return fmt.Errorf("validation of cca-platform-claims failed: %w", err)
	}

	if err := e.RealmClaims.Validate(); err != nil {
		return fmt.Errorf("validation of cca-realm-claims failed: %w", err)
	}

	return nil
}

// UnmarshalCBOR extracts the realm and platform tokens from the serialized
// collection.
func (e *Evidence) UnmarshalCBOR(buf []byte) error {

	var tag cbortag.RawTag
	if err := tag.UnmarshalCBOR(buf); err != nil {
			return fmt.Errorf("unmarshal top-level CBOR Tag: %w", err)
	}
	
	switch tag.Number {
		case 907:    // New CMW formed token
		{
			cmwCollection := &CBORCMWCollection{}

			err := dm.Unmarshal(buf, cmwCollection)
			if err != nil {
				return fmt.Errorf("CBOR decoding of CCA evidence failed: %w", err)
			}

			if cmwCollection.PlatformTokenColl.TokenStr == nil {
					return fmt.Errorf("CCA platform token not set")
			}

			if cmwCollection.RealmTokenColl.TokenStr == nil {
					return fmt.Errorf("CCA realm token not set")
			}
			e.platformTokenRaw = cmwCollection.PlatformTokenColl.TokenStr
			e.realmTokenRaw = cmwCollection.RealmTokenColl.TokenStr
		}
		case 399:    // legacy EAT collection token
		{
			eatCollection := &CBORCollection{}

			err := dm.Unmarshal(buf, eatCollection)
			if err != nil {
				return fmt.Errorf("CBOR decoding of CCA evidence failed: %w", err)
			}

			if eatCollection.PlatformToken == nil {
					return fmt.Errorf("CCA platform token not set")
			}

			if eatCollection.RealmToken == nil {
					return fmt.Errorf("CCA realm token not set")
			}
			e.platformTokenRaw = eatCollection.PlatformToken
			e.realmTokenRaw = eatCollection.RealmToken
		}

		default:
		{
			// note: match fxamaker decode error message to satisfy test expectation
			return fmt.Errorf("CBOR decoding of CCA evidence failed: cbor: wrong tag number for ccatoken.CBORCollection, got [%d], expected [907]", tag.Number)
		}
	}

	// This will decode both platform and realm claims
	err := e.decodeClaimsFromCBOR()
	if err != nil {
		return fmt.Errorf("decoding of CCA evidence failed: %w", err)
	}

	return nil
}

// MarshalJSON encodes the realm and platform claims into a JSON object.
func (e *Evidence) MarshalJSON() ([]byte, error) {
	pj, err := platform.EncodeClaimsToJSON(e.PlatformClaims)
	if err != nil {
		return nil, fmt.Errorf("error serializing platform claims: %w", err)
	}

	rj, err := realm.EncodeClaimsToJSON(e.RealmClaims)
	if err != nil {
		return nil, fmt.Errorf("error serializing realm claims: %w", err)
	}

	c := JSONCollection{
		PlatformToken: pj,
		RealmToken:    rj,
	}

	return json.Marshal(c)
}

// UnmarshalJSON extracts the realm and platform tokens from the serialized
// collection.
func (e *Evidence) UnmarshalJSON(data []byte) error {
	p, r, err := e.doUnmarshalJSON(data)
	if err != nil {
		return err
	}

	e.SetUnvalidatedClaims(p, r)

	return nil
}

// SetClaims sets the specified realm and platform claims in the evidence aend
// ensures they are valid.
func (e *Evidence) SetClaims(p platform.IClaims, r realm.IClaims) error {
	if p == nil || r == nil {
		return errors.New("nil claims supplied")
	}

	e.SetUnvalidatedClaims(p, r)

	// This call will set the nonce in the platform claims based on the RAK and
	// hash algorithm in the realm claims.
	if err := e.bind(); err != nil {
		return fmt.Errorf("tokens binding failed: %w", err)
	}

	if err := p.Validate(); err != nil {
		return fmt.Errorf("validation of cca-platform-claims failed: %w", err)
	}

	if err := r.Validate(); err != nil {
		return fmt.Errorf("validation of cca-realm-claims failed: %w", err)
	}

	return nil
}

// SetUnvalidatedClaims is the same as SetClaims but without validation.
func (e *Evidence) SetUnvalidatedClaims(p platform.IClaims, r realm.IClaims) {
	e.RealmClaims = r
	e.PlatformClaims = p

	// This call will set the nonce in the platform claims based on the RAK and
	// hash algorithm in the realm claims.
	if p != nil && r != nil {
		_ = e.bind()
	}
}

// ValidateAndSign validates and then signs the given evidence using the
// supplied Platform and Realm Signer and returns the complete CCA token as
// CBOR bytes
func (e *Evidence) ValidateAndSign(pSigner cose.Signer, rSigner cose.Signer) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}

	return e.Sign(pSigner, rSigner)
}

// Sign signs the given evidence using the supplied Platform and Realm Signer
// and returns the complete CCA token as CBOR bytes
func (e *Evidence) Sign(pSigner cose.Signer, rSigner cose.Signer) ([]byte, error) {
	if pSigner == nil || rSigner == nil {
		return nil, fmt.Errorf("nil signer(s) supplied")
	}

	platformToken, err := signClaims(e.PlatformClaims, pSigner)
	if err != nil {
		return nil, fmt.Errorf("signing platform claims: %w", err)
	}
	realmToken, err := signClaims(e.RealmClaims, rSigner)
	if err != nil {
		return nil, fmt.Errorf("signing realm claims: %w", err)
	}

	platCollect := CMWCollectionEntry{
		Coaptype: 263,
		TokenStr: &platformToken,
	}

	realmCollect := CMWCollectionEntry{
		Coaptype: 263,
		TokenStr: &realmToken,
	}

	cmwCollection := &CBORCMWCollection{
		PlatformTokenColl: platCollect,
		RealmTokenColl:    realmCollect,
	}

	// We do now have CcaPlatform and Realm Token setup correctly.
	buf, err := em.Marshal(cmwCollection)
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding of CCA token failed: %w", err)
	}


	return buf, nil
}

// Verify verifies the CCA evidence using the supplied platform public key.
// The integrity of the realm token is checked by extracting the inlined realm
// public key.  This also checks the correctness of the chaining between
// platform and realm tokens.
func (e *Evidence) Verify(iak crypto.PublicKey) error {

	if e.platformTokenRaw == nil && e.realmTokenRaw == nil {
			return fmt.Errorf("no message found")
	}

	// Check CCA Platform Token
	if e.platformTokenRaw == nil {
			return fmt.Errorf("missing CCA platform Token")
	}

	// First verify the platform token
	if err := e.verifyCOSEToken(*e.platformTokenRaw, iak); err != nil {
			return fmt.Errorf("unable to verify platform token: %w", err)
	}

	// Check CCA Realm Token
	if e.realmTokenRaw == nil {
			return fmt.Errorf("missing CCA realm Token")
	}

	// extract RAK from the realm token
	rawRAK, err := e.RealmClaims.GetPubKey()
	if err != nil {
		return fmt.Errorf("extracting RAK from the realm token: %w", err)
	}

	var rak *ecdsa.PublicKey

	_, err = e.RealmClaims.GetProfile()
	if err != nil {
		switch err {
		case psatoken.ErrOptionalClaimMissing:
			rak, err = realm.ECDSAPublicKeyFromRaw(rawRAK)
			if err != nil {
				return fmt.Errorf("decoding RAK: %w", err)
			}
		default:
			return fmt.Errorf("extracting realm profile: %w", err)
		}
	} else {
		rak, err = realm.ECDSAPublicKeyFromCOSEKey(rawRAK)
		if err != nil {
			return fmt.Errorf("decoding RAK: %w", err)
		}
	}

	// Next verify the realm token
	if err := e.verifyCOSEToken(*e.realmTokenRaw, rak); err != nil {
			return fmt.Errorf("unable to verify realm token: %w", err)
	}

	// check the collection binding
	if err := e.checkBinding(); err != nil {
		return fmt.Errorf("binding verification failed: %w", err)
	}

	return nil
}

// GetInstanceID returns the InstanceID from CCA platform token
// or a nil pointer if no suitable InstanceID could be located.
func (e *Evidence) GetInstanceID() *[]byte {
	instID, err := e.PlatformClaims.GetInstID()
	if err != nil {
		return nil
	}
	return &instID
}

// GetImplementationID returns the ImplementationID from CCA platform token
// or a nil pointer if no suitable ImplementationID could be located.
func (e *Evidence) GetImplementationID() *[]byte {
	implID, err := e.PlatformClaims.GetImplID()
	if err != nil {
		return nil
	}
	return &implID
}

// GetRealmPublicKey returns the RMM Public Key
// RMM Public Key is used to verify the signature on the Realm Token
func (e *Evidence) GetRealmPublicKey() *[]byte {
	pubKey, err := e.RealmClaims.GetPubKey()
	if err != nil {
		return nil
	}
	return &pubKey
}

func (e *Evidence) doUnmarshalJSON(data []byte) (platform.IClaims, realm.IClaims, error) {
	var c map[string]json.RawMessage
	var err error

	if err = json.Unmarshal(data, &c); err != nil {
		return nil, nil, fmt.Errorf("unmarshaling CCA claims: %w", err)
	}

	// platform
	var p platform.IClaims
	platToken, ok := c["cca-platform-token"]
	if ok && platToken != nil {
		p, err = platform.DecodeClaimsFromJSON(platToken)
		if err != nil {
			return nil, nil, fmt.Errorf("unmarshaling platform claims: %w", err)
		}
	}

	// realm
	var r realm.IClaims
	realmToken, ok := c["cca-realm-delegated-token"]
	if ok && realmToken != nil {
		r, err = realm.DecodeClaimsFromJSON(realmToken)
		if err != nil {
			return nil, nil, fmt.Errorf("unmarshaling realm claims: %w", err)
		}
	}

	return p, r, nil
}

func (e *Evidence) decodeClaimsFromCBOR() error {
	if e.realmTokenRaw == nil || e.platformTokenRaw == nil {
			panic("broken invariant: nil tokens")
	}

	// decode platform
	pSign1 := cose.NewSign1Message()

	if err := pSign1.UnmarshalCBOR(*e.platformTokenRaw); err != nil {
			return fmt.Errorf("failed CBOR decoding for CWT: %w", err)
	}

	PlatformClaims, err := platform.DecodeClaimsFromCBOR(pSign1.Payload)
	if err != nil {
		return fmt.Errorf("failed CBOR decoding of CCA platform claims: %w", err)
	}
	e.PlatformClaims = PlatformClaims

	// decode realm
	rSign1 := cose.NewSign1Message()

	if err = rSign1.UnmarshalCBOR(*e.realmTokenRaw); err != nil {
			return fmt.Errorf("failed CBOR decoding for CWT: %w", err)
	}

	RealmClaims, err := realm.DecodeClaimsFromCBOR(rSign1.Payload)
	if err != nil {
		return fmt.Errorf("failed CBOR decoding of CCA realm claims: %w", err)
	}
	e.RealmClaims = RealmClaims

	return nil
}

func signClaims(claims any, signer cose.Signer) ([]byte, error) {
	claimSet, err := em.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding the payload: %w", err)
	}

	return signPayload(claimSet, signer)
}

func signPayload(payload []byte, signer cose.Signer) ([]byte, error) {
	alg := signer.Algorithm()
	if strings.Contains(alg.String(), "unknown algorithm value") {
		return nil, errors.New("signer has no algorithm")
	}

	message := cose.NewSign1Message()
	message.Payload = payload
	message.Headers.Protected.SetAlgorithm(alg)

	err := message.Sign(rand.Reader, []byte(""), signer)
	if err != nil {
		return nil, fmt.Errorf("COSE Sign1 failed: %w", err)
	}

	sign1, err := message.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding the COSE Sign1: %w", err)
	}

	return sign1, nil
}

func (e *Evidence) bind() error {
	binder, err := e.computeBinder()
	if err != nil {
		return fmt.Errorf("computing binder value: %w", err)
	}

	if err := e.PlatformClaims.SetNonce(binder); err != nil {
		return fmt.Errorf("setting binder value: %w", err)
	}

	return nil
}

func (e *Evidence) checkBinding() error {
	binder, err := e.computeBinder()
	if err != nil {
		return fmt.Errorf("computing binder: %w", err)
	}

	// extract platform nonce
	pNonce, err := e.PlatformClaims.GetNonce()
	if err != nil {
		return fmt.Errorf("extracting nonce from the platform token: %w", err)
	}

	// compare expected against actual binder value
	if !reflect.DeepEqual(binder, pNonce) {
		return errors.New("platform nonce does not match RAK hash")
	}

	return nil
}

func (e *Evidence) computeBinder() ([]byte, error) {
	// extract rak from realm token
	rak, err := e.RealmClaims.GetPubKey()
	if err != nil {
		return nil, fmt.Errorf("extracting RAK from the realm token: %w", err)
	}

	// extract rak hash alg from realm token
	alg, err := e.RealmClaims.GetPubKeyHashAlgID()
	if err != nil {
		return nil, fmt.Errorf("extracting RAK hash algorithm from the realm token: %w", err)
	}

	// map hash alg string to hash function
	h, err := hashStringToID(alg)
	if err != nil {
		return nil, fmt.Errorf("mapping RAK hash algorithm: %w", err)
	}

	// compute the expected binder value
	h.Write(rak)

	return h.Sum(nil), nil
}

func hashStringToID(s string) (hash.Hash, error) {
	switch s {
	case "sha-224":
		return sha256.New224(), nil
	case "sha-256":
		return sha256.New(), nil
	case "sha-384":
		return sha512.New384(), nil
	case "sha-512":
		return sha512.New(), nil
	}
	return nil, fmt.Errorf("hash algorithm %q not known", s)
}

func (e *Evidence) verifyCOSEToken(token []byte, pk crypto.PublicKey) error {
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
