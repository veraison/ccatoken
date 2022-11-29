package ccatoken

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"strings"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
	"github.com/veraison/psatoken"
)

type CBORCollection struct {
	PlatformToken cbor.RawMessage `cbor:"44234,keyasint"`
	RealmToken    cbor.RawMessage `cbor:"44241,keyasint"`
}

type JSONCollection struct {
	PlatformToken json.RawMessage `json:"cca-platform-token"`
	RealmToken    json.RawMessage `json:"cca-realm-delegated-token"`
}

// Evidence is a wrapper around CcaToken
type Evidence struct {
	PlatformClaims psatoken.IClaims
	RealmClaims    IClaims
	collection     *CBORCollection
}

func (e *Evidence) MarshalJSON() ([]byte, error) {
	if e.PlatformClaims == nil || e.RealmClaims == nil {
		return nil, errors.New("invalid evidence")
	}

	pj, err := e.PlatformClaims.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("error serializing platform claims: %w", err)
	}

	rj, err := e.RealmClaims.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("error serializing realm claims: %w", err)
	}

	c := JSONCollection{
		PlatformToken: pj,
		RealmToken:    rj,
	}

	return json.Marshal(c)
}

func (e *Evidence) UnmarshalJSON(data []byte) error {
	var c JSONCollection

	if err := json.Unmarshal(data, &c); err != nil {
		return fmt.Errorf("unmarshaling CCA claims: %w", err)
	}

	// platform
	p := &psatoken.CcaPlatformClaims{}

	if err := json.Unmarshal(c.PlatformToken, &p); err != nil {
		return fmt.Errorf("unmarshaling platform claims: %w", err)
	}

	// realm
	r := &RealmClaims{}

	if err := json.Unmarshal(c.RealmToken, &r); err != nil {
		return fmt.Errorf("unmarshaling realm claims: %w", err)
	}

	if err := e.SetClaims(p, r); err != nil {
		return fmt.Errorf("setting claims: %w", err)
	}

	return nil
}

func (e *Evidence) SetClaims(p psatoken.IClaims, r IClaims) error {
	if p == nil || r == nil {
		return errors.New("nil claims supplied")
	}

	e.RealmClaims = r
	e.PlatformClaims = p

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

// Sign signs the given evidence using the supplied Platform and Realm Signer
// and returns the complete CCA token as CBOR bytes
func (e *Evidence) Sign(pSigner cose.Signer, rSigner cose.Signer) ([]byte, error) {
	if e.PlatformClaims == nil || e.RealmClaims == nil {
		return nil, fmt.Errorf("claims not set in evidence")
	}

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

	e.collection = &CBORCollection{
		PlatformToken: platformToken,
		RealmToken:    realmToken,
	}

	// We do now have CcaPlatform and Realm Token setup correctly.
	buf, err := em.Marshal(e.collection)
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding of CCA token failed: %w", err)
	}

	return buf, nil
}

type CBORClaimer interface {
	ToCBOR() ([]byte, error)
}

func signClaims(claimer CBORClaimer, signer cose.Signer) ([]byte, error) {
	alg := signer.Algorithm()
	if strings.Contains(alg.String(), "unknown algorithm value") {
		return nil, errors.New("signer has no algorithm")
	}

	claimSet, err := claimer.ToCBOR()
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding the payload: %w", err)
	}

	message := cose.NewSign1Message()
	message.Payload = claimSet
	message.Headers.Protected.SetAlgorithm(alg)

	err = message.Sign(rand.Reader, []byte(""), signer)
	if err != nil {
		return nil, fmt.Errorf("COSE Sign1 failed: %w", err)
	}

	sign1, err := message.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding the COSE Sign1: %w", err)
	}

	return sign1, nil
}

// FromCBOR extracts and validates the realm and platform tokens from the
// serialized collection.
func (e *Evidence) FromCBOR(buf []byte) error {
	e.collection = &CBORCollection{}

	err := dm.Unmarshal(buf, e.collection)
	if err != nil {
		return fmt.Errorf("cbor decoding of CCA evidence failed: %w", err)
	}

	if e.collection.PlatformToken == nil {
		return fmt.Errorf("CCA platform token not set")
	}

	if e.collection.RealmToken == nil {
		return fmt.Errorf("CCA realm token not set")
	}

	// This will decode both platform and realm claims
	err = e.decodeClaims()
	if err != nil {
		return fmt.Errorf("decoding of CCA evidence failed: %w", err)
	}

	return nil
}

func (e *Evidence) decodeClaims() error {
	// decode platform
	pSign1 := cose.NewSign1Message()

	if err := pSign1.UnmarshalCBOR(e.collection.PlatformToken); err != nil {
		return fmt.Errorf("failed CBOR decoding for CWT: %w", err)
	}

	PlatformClaims, err := psatoken.DecodeClaims(pSign1.Payload)
	if err != nil {
		return fmt.Errorf("failed CBOR decoding of CCA platform claims: %w", err)
	}
	e.PlatformClaims = PlatformClaims

	// decode realm
	rSign1 := cose.NewSign1Message()

	if err = rSign1.UnmarshalCBOR(e.collection.RealmToken); err != nil {
		return fmt.Errorf("failed CBOR decoding for CWT: %w", err)
	}

	RealmClaims, err := DecodeClaims(rSign1.Payload)
	if err != nil {
		return fmt.Errorf("failed CBOR decoding of CCA realm claims: %w", err)
	}
	e.RealmClaims = RealmClaims

	return nil
}

// Verify verifies the CCA evidence using the supplied platform public key.
// The integrity of the realm token is checked by extracting the inlined realm
// public key.  This also checks the correctness of the chaining between
// platform and realm tokens.
func (e *Evidence) Verify(iak crypto.PublicKey) error {
	if e.collection == nil {
		return fmt.Errorf("no message found")
	}

	// Check CCA Platform Token
	if e.collection.PlatformToken == nil {
		return fmt.Errorf("missing CCA platform Token")
	}

	// First verify the platform token
	if err := e.verifyCOSEToken(e.collection.PlatformToken, iak); err != nil {
		return fmt.Errorf("unable to verify platform token: %w", err)
	}

	// Check CCA Realm Token
	if e.collection.RealmToken == nil {
		return fmt.Errorf("missing CCA realm Token")
	}

	// extract RAK from the realm token
	rawRAK, err := e.RealmClaims.GetPubKey()
	if err != nil {
		return fmt.Errorf("extracting RAK from the realm token: %w", err)
	}

	rak, err := ecdsaPublicKeyFromRaw(rawRAK)
	if err != nil {
		return fmt.Errorf("decoding RAK: %w", err)
	}

	// Next verify the realm token
	if err := e.verifyCOSEToken(e.collection.RealmToken, rak); err != nil {
		return fmt.Errorf("unable to verify realm token: %w", err)
	}

	// check the collection binding
	if err := e.checkBinding(); err != nil {
		return fmt.Errorf("binding verification failed: %w", err)
	}

	return nil
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
