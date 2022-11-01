package ccatoken

import (
	"crypto"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cose "github.com/veraison/go-cose"
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

func TestEvidence_sign_and_verify_ok(t *testing.T) {
	rSigner := signerFromJWK(t, testRAK)
	pSigner := signerFromJWK(t, testIAK)

	var EvidenceIn Evidence

	err := EvidenceIn.SetCcaPlatformClaims(
		mustBuildValidCcaPlatformClaims(t, true),
	)
	assert.NoError(t, err)

	err = EvidenceIn.SetCcaRealmClaims(
		mustBuildValidCcaRealmClaims(t),
	)
	assert.NoError(t, err)

	ccaToken, err := EvidenceIn.Sign(pSigner, rSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("CCA evidence : %x\n", ccaToken)

	var EvidenceOut Evidence

	err = EvidenceOut.FromCBOR(ccaToken)
	assert.NoError(t, err, "CCA token decoding failed")

	verifier := pubKeyFromJWK(t, testIAK)

	err = EvidenceOut.Verify(verifier)
	assert.NoError(t, err)
}

func TestEvidence_sign_and_verify_platform_key_mismatch(t *testing.T) {
	rSigner := signerFromJWK(t, testRAK)
	pSigner := signerFromJWK(t, testIAK)

	var EvidenceIn Evidence

	err := EvidenceIn.SetCcaPlatformClaims(
		mustBuildValidCcaPlatformClaims(t, true),
	)
	assert.NoError(t, err)

	err = EvidenceIn.SetCcaRealmClaims(
		mustBuildValidCcaRealmClaims(t),
	)
	assert.NoError(t, err)

	ccaToken, err := EvidenceIn.Sign(pSigner, rSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("CCA evidence : %x\n", ccaToken)

	var EvidenceOut Evidence

	err = EvidenceOut.FromCBOR(ccaToken)
	assert.NoError(t, err, "CCA token decoding failed")

	mismatchedVerifier := pubKeyFromJWK(t, testAltIAK)

	err = EvidenceOut.Verify(mismatchedVerifier)
	assert.EqualError(t, err, "unable to verify platform token: verification error")
}

func TestEvidence_GetInstanceID_ok(t *testing.T) {
	var EvidenceIn Evidence
	err := EvidenceIn.SetCcaPlatformClaims(mustBuildValidCcaPlatformClaims(t, true))
	require.NoError(t, err)

	expected := &testInstID
	actual := EvidenceIn.GetInstanceID()
	assert.Equal(t, expected, actual)
}

func TestEvidence_GetImplementationID_ok(t *testing.T) {
	var EvidenceIn Evidence

	err := EvidenceIn.SetCcaPlatformClaims(mustBuildValidCcaPlatformClaims(t, true))
	require.NoError(t, err)

	expected := &testImplementationID

	actual := EvidenceIn.GetImplementationID()
	assert.Equal(t, expected, actual)
}

func TestEvidence_GetRealmPubKey_ok(t *testing.T) {
	var EvidenceIn Evidence

	err := EvidenceIn.SetCcaRealmClaims(mustBuildValidCcaRealmClaims(t))
	require.NoError(t, err)

	expected := &testRAKPubRaw

	actual := EvidenceIn.GetRealmPublicKey()
	assert.Equal(t, expected, actual)
}

func TestEvidence_sign_missing_realm_claims(t *testing.T) {
	var (
		EvidenceIn Evidence
		unused     cose.Signer
	)

	err := EvidenceIn.SetCcaPlatformClaims(
		mustBuildValidCcaPlatformClaims(t, true),
	)
	require.NoError(t, err)

	_, err = EvidenceIn.Sign(unused, unused)
	assert.EqualError(t, err, "missing realm claims in evidence")
}

func TestEvidence_sign_missing_platform_claims(t *testing.T) {
	var (
		EvidenceIn Evidence
		unused     cose.Signer
	)

	err := EvidenceIn.SetCcaRealmClaims(
		mustBuildValidCcaRealmClaims(t),
	)
	require.NoError(t, err)

	_, err = EvidenceIn.Sign(unused, unused)
	assert.EqualError(t, err, "missing platform claims in evidence")
}

func TestEvidence_Verify_no_message(t *testing.T) {
	var (
		empty  Evidence
		unused crypto.PublicKey
	)

	err := empty.Verify(unused)
	assert.EqualError(t, err, "no message found")
}

func TestEvidence_FromCBOR_Malformed_token(t *testing.T) {
	wrongTag := []byte{
		0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x58, 0x1e, 0xa1, 0x19, 0x01,
		0x09, 0x78, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x61, 0x72,
		0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x73, 0x61, 0x2f, 0x33, 0x2e,
		0x30, 0x2e, 0x30, 0x44, 0xde, 0xad, 0xbe, 0xef,
	}

	expectedErr := `cbor decoding of CCA evidence failed: cbor: wrong tag number for ccatoken.Token, got [18], expected [399]`

	var e Evidence
	err := e.FromCBOR(wrongTag)

	assert.EqualError(t, err, expectedErr)
}
