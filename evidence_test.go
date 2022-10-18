package ccatoken

import (
	"crypto"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/psatoken"
)

func mustBuildValidCcaPlatformClaims(t *testing.T, includeOptional bool) psatoken.IClaims {
	c, err := psatoken.NewClaims(testCcaProfile)
	require.NoError(t, err)

	err = c.SetSecurityLifeCycle(testPlatformLifecycleSecured)
	require.NoError(t, err)

	err = c.SetImplID(testImplementationID)
	require.NoError(t, err)

	err = c.SetNonce(testNonce)
	require.NoError(t, err)

	err = c.SetInstID(testInstID)
	require.NoError(t, err)

	err = c.SetSoftwareComponents(testSoftwareComponents)
	require.NoError(t, err)

	err = c.SetHashAlgID(testHashAlgID)
	require.NoError(t, err)

	err = c.SetConfig(testConfig)
	require.NoError(t, err)

	if includeOptional {
		err = c.SetVSI(testVSI)
		require.NoError(t, err)
	}

	return c
}

func TestEvidence_sign_and_verify_identical_key_ok(t *testing.T) {
	PlatformSigner := signerFromJWK(t, testECKeyA)
	RealmSigner := signerFromJWK(t, testECKeyA)
	var EvidenceIn CcaEvidence

	err := EvidenceIn.SetCcaPlatformClaims(mustBuildValidCcaPlatformClaims(t, true))
	assert.NoError(t, err)

	err = EvidenceIn.SetCcaRealmClaims(mustBuildValidCcaRealmClaims(t))
	assert.NoError(t, err)

	cwt, err := EvidenceIn.Sign(PlatformSigner, RealmSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("CCA evidence : %x\n", cwt)

	var EvidenceOut CcaEvidence

	err = EvidenceOut.FromCBOR(cwt)
	assert.NoError(t, err, "evidence contaiting CCA token decoding failed")

	pkPlatform := pubKeyFromJWK(t, testECKeyA)
	pkRealm := pubKeyFromJWK(t, testECKeyA)
	err = EvidenceOut.Verify(pkPlatform, pkRealm)
	assert.NoError(t, err)
}

func TestEvidence_sign_and_verify_non_identical_key_ok(t *testing.T) {
	PlatformSigner := signerFromJWK(t, testECKeyB)
	RealmSigner := signerFromJWK(t, testECKeyA)
	var EvidenceIn CcaEvidence

	err := EvidenceIn.SetCcaPlatformClaims(mustBuildValidCcaPlatformClaims(t, true))
	assert.NoError(t, err)

	err = EvidenceIn.SetCcaRealmClaims(mustBuildValidCcaRealmClaims(t))
	assert.NoError(t, err)

	cwt, err := EvidenceIn.Sign(PlatformSigner, RealmSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("CCA evidence : %x\n", cwt)

	var EvidenceOut CcaEvidence

	err = EvidenceOut.FromCBOR(cwt)
	assert.NoError(t, err, "evidence contaiting CCA token decoding failed")

	pkPlatform := pubKeyFromJWK(t, testECKeyB)
	pkRealm := pubKeyFromJWK(t, testECKeyA)
	err = EvidenceOut.Verify(pkPlatform, pkRealm)
	assert.NoError(t, err)
}

func TestEvidence_sign_and_verify_realm_key_mismatch(t *testing.T) {
	PlatformSigner := signerFromJWK(t, testECKeyB)
	RealmSigner := signerFromJWK(t, testECKeyA)
	var EvidenceIn CcaEvidence

	err := EvidenceIn.SetCcaPlatformClaims(mustBuildValidCcaPlatformClaims(t, true))
	assert.NoError(t, err)

	err = EvidenceIn.SetCcaRealmClaims(mustBuildValidCcaRealmClaims(t))
	assert.NoError(t, err)

	cwt, err := EvidenceIn.Sign(PlatformSigner, RealmSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("CCA evidence : %x\n", cwt)

	var EvidenceOut CcaEvidence

	err = EvidenceOut.FromCBOR(cwt)
	assert.NoError(t, err, "evidence contaiting CCA token decoding failed")

	pkPlatform := pubKeyFromJWK(t, testECKeyB)
	pkRealm := pubKeyFromJWK(t, testECKeyB)
	err = EvidenceOut.Verify(pkPlatform, pkRealm)
	assert.EqualError(t, err, "unable to verify realm token: verification error")
}

func TestEvidence_sign_and_verify_platform_key_mismatch(t *testing.T) {
	PlatformSigner := signerFromJWK(t, testECKeyA)
	RealmSigner := signerFromJWK(t, testECKeyA)
	var EvidenceIn CcaEvidence

	err := EvidenceIn.SetCcaPlatformClaims(mustBuildValidCcaPlatformClaims(t, true))
	assert.NoError(t, err)

	err = EvidenceIn.SetCcaRealmClaims(mustBuildValidCcaRealmClaims(t))
	assert.NoError(t, err)

	cwt, err := EvidenceIn.Sign(PlatformSigner, RealmSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("CCA evidence : %x\n", cwt)

	var EvidenceOut CcaEvidence

	err = EvidenceOut.FromCBOR(cwt)
	assert.NoError(t, err, "evidence contaiting CCA token decoding failed")

	pkPlatform := pubKeyFromJWK(t, testECKeyC)
	pkRealm := pubKeyFromJWK(t, testECKeyA)
	err = EvidenceOut.Verify(pkPlatform, pkRealm)
	assert.EqualError(t, err, "unable to verify platform token: verification error")
}

func TestEvidence_sign_and_verify_platform_alg_mismatch(t *testing.T) {
	PlatformSigner := signerFromJWK(t, testECKeyA)
	RealmSigner := signerFromJWK(t, testECKeyB)
	var EvidenceIn CcaEvidence

	err := EvidenceIn.SetCcaPlatformClaims(mustBuildValidCcaPlatformClaims(t, true))
	assert.NoError(t, err)

	err = EvidenceIn.SetCcaRealmClaims(mustBuildValidCcaRealmClaims(t))
	assert.NoError(t, err)

	cwt, err := EvidenceIn.Sign(PlatformSigner, RealmSigner)
	assert.NoError(t, err, "signing failed")

	var EvidenceOut CcaEvidence

	err = EvidenceOut.FromCBOR(cwt)
	assert.NoError(t, err, "evidence containing CCA token decoding failed")

	pkRealm := pubKeyFromJWK(t, testECKeyB)
	var pkPlatform crypto.PublicKey
	err = EvidenceOut.Verify(pkPlatform, pkRealm)
	assert.EqualError(t, err, "unable to verify platform token: unable to instantiate verifier: ES256: algorithm mismatch")
}

func TestEvidence_sign_and_verify_realm_alg_mismatch(t *testing.T) {
	PlatformSigner := signerFromJWK(t, testECKeyA)
	RealmSigner := signerFromJWK(t, testECKeyB)
	var EvidenceIn CcaEvidence

	err := EvidenceIn.SetCcaPlatformClaims(mustBuildValidCcaPlatformClaims(t, true))
	assert.NoError(t, err)

	err = EvidenceIn.SetCcaRealmClaims(mustBuildValidCcaRealmClaims(t))
	assert.NoError(t, err)

	cwt, err := EvidenceIn.Sign(PlatformSigner, RealmSigner)
	assert.NoError(t, err, "signing failed")

	var EvidenceOut CcaEvidence

	err = EvidenceOut.FromCBOR(cwt)
	assert.NoError(t, err, "evidence containing CCA token decoding failed")

	pkPlatform := pubKeyFromJWK(t, testECKeyA)
	var pkRealm crypto.PublicKey
	err = EvidenceOut.Verify(pkPlatform, pkRealm)
	assert.EqualError(t, err, "unable to verify realm token: unable to instantiate verifier: ES256: algorithm mismatch")
}

func TestEvidence_GetInstanceID_ok(t *testing.T) {
	var EvidenceIn CcaEvidence
	err := EvidenceIn.SetCcaPlatformClaims(mustBuildValidCcaPlatformClaims(t, true))
	require.NoError(t, err)

	expected := &testInstID
	actual := EvidenceIn.GetInstanceID()
	assert.Equal(t, expected, actual)
}

func TestEvidence_GetImplementationID_ok(t *testing.T) {
	var EvidenceIn CcaEvidence
	err := EvidenceIn.SetCcaPlatformClaims(mustBuildValidCcaPlatformClaims(t, true))
	require.NoError(t, err)

	expected := &testImplementationID
	actual := EvidenceIn.GetImplementationID()
	assert.Equal(t, expected, actual)
}

func TestEvidence_GetRealmPubKey_ok(t *testing.T) {
	var EvidenceIn CcaEvidence
	err := EvidenceIn.SetCcaRealmClaims(mustBuildValidCcaRealmClaims(t))
	require.NoError(t, err)

	expected := &testPubKey
	actual := EvidenceIn.GetRealmPublicKey()
	assert.Equal(t, expected, actual)
}

func TestEvidence_sign_and_verify_realm_pem_ok(t *testing.T) {
	PlatformSigner := signerFromJWK(t, testECKeyA)
	jwKey, err := getJwkKeyFromPemKey(testPEMKey)
	assert.NoError(t, err)
	RealmSigner := signerFromJwKey(t, jwKey)

	var EvidenceIn CcaEvidence

	err = EvidenceIn.SetCcaPlatformClaims(mustBuildValidCcaPlatformClaims(t, true))
	assert.NoError(t, err)

	err = EvidenceIn.SetCcaRealmClaims(mustBuildValidCcaRealmClaims(t))
	assert.NoError(t, err)

	cwt, err := EvidenceIn.Sign(PlatformSigner, RealmSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("CCA evidence : %x\n", cwt)
	pkPlatform := pubKeyFromJWK(t, testECKeyA)
	pkRealm := pubKeyFromJwKey(t, jwKey)
	var EvidenceOut CcaEvidence
	err = EvidenceOut.FromCBOR(cwt)
	assert.NoError(t, err, "evidence contaiting CCA token decoding failed")
	err = EvidenceOut.Verify(pkPlatform, pkRealm)
	assert.NoError(t, err)
}

func TestEvidence_sign_missing_realm_claims(t *testing.T) {
	var EvidenceIn CcaEvidence
	ps := signerFromJWK(t, testECKeyA)
	rs := signerFromJWK(t, testECKeyB)

	err := EvidenceIn.SetCcaPlatformClaims(mustBuildValidCcaPlatformClaims(t, true))
	require.NoError(t, err)
	_, err = EvidenceIn.Sign(ps, rs)
	assert.EqualError(t, err, "missing realm claims in evidence")
}

func TestEvidence_sign_missing_platform_claims(t *testing.T) {
	var EvidenceIn CcaEvidence
	ps := signerFromJWK(t, testECKeyA)
	rs := signerFromJWK(t, testECKeyB)

	err := EvidenceIn.SetCcaRealmClaims(mustBuildValidCcaRealmClaims(t))
	require.NoError(t, err)
	_, err = EvidenceIn.Sign(ps, rs)
	assert.EqualError(t, err, "missing platform claims in evidence")
}

func TestEvidence_Verify_no_message(t *testing.T) {
	evidence := CcaEvidence{}
	var pkPlatform crypto.PublicKey
	var pkRealm crypto.PublicKey

	err := evidence.Verify(pkPlatform, pkRealm)
	assert.EqualError(t, err, "no message found")
}

func TestEvidence_FromCBOR_Malformed_token(t *testing.T) {
	tv := []byte{
		0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x58, 0x1e, 0xa1, 0x19, 0x01,
		0x09, 0x78, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x61, 0x72,
		0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x73, 0x61, 0x2f, 0x33, 0x2e,
		0x30, 0x2e, 0x30, 0x44, 0xde, 0xad, 0xbe, 0xef,
	}

	e := CcaEvidence{}
	err := e.FromCBOR(tv)
	expectedErr := `cbor decoding of CCA evidence failed: cbor: wrong tag number for ccatoken.CcaToken, got [18], expected [399]`
	assert.EqualError(t, err, expectedErr)
}
