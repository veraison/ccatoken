package ccatoken

import (
	"crypto"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/ccatoken/platform"
	"github.com/veraison/ccatoken/realm"
	"github.com/veraison/go-cose"
)

func mustBuildValidCcaRealmClaims(t *testing.T) realm.IClaims {
	c := realm.NewClaims()

	err := c.SetChallenge(testChallenge)
	require.NoError(t, err)

	err = c.SetPersonalizationValue(testPersonalizationVal)
	require.NoError(t, err)

	err = c.SetInitialMeasurement(testInitMeas)
	require.NoError(t, err)

	err = c.SetExtensibleMeasurements(testExtensibleMeas)
	require.NoError(t, err)

	err = c.SetHashAlgID(testHashAlgID)
	require.NoError(t, err)

	err = c.SetPubKey(testRAKPubRaw)
	require.NoError(t, err)

	err = c.SetPubKeyHashAlgID(testPubKeyHashAlgID)
	require.NoError(t, err)

	return c
}

func mustBuildValidPlatformClaims(t *testing.T, includeOptional bool) platform.IClaims {
	c := platform.NewClaims()

	err := c.SetSecurityLifeCycle(testPlatformLifecycleSecured)
	require.NoError(t, err)

	err = c.SetImplID(testImplementationID)
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

	err := EvidenceIn.SetClaims(
		mustBuildValidPlatformClaims(t, true),
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

func TestEvidence_sign_and_verify_bad_binder(t *testing.T) {
	rSigner := signerFromJWK(t, testRAK)
	pSigner := signerFromJWK(t, testIAK)

	var EvidenceIn Evidence

	err := EvidenceIn.SetClaims(
		mustBuildValidPlatformClaims(t, true),
		mustBuildValidCcaRealmClaims(t),
	)
	assert.NoError(t, err)

	// tamper with the binder value
	err = EvidenceIn.PlatformClaims.SetNonce([]byte("tampered binder!tampered binder!"))
	require.NoError(t, err, "overriding binder")

	ccaToken, err := EvidenceIn.Sign(pSigner, rSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("CCA evidence : %x\n", ccaToken)

	var EvidenceOut Evidence

	err = EvidenceOut.FromCBOR(ccaToken)
	assert.NoError(t, err, "CCA token decoding failed")

	verifier := pubKeyFromJWK(t, testIAK)

	err = EvidenceOut.Verify(verifier)
	assert.EqualError(t, err, "binding verification failed: platform nonce does not match RAK hash")
}

func TestEvidence_sign_and_verify_platform_key_mismatch(t *testing.T) {
	rSigner := signerFromJWK(t, testRAK)
	pSigner := signerFromJWK(t, testIAK)

	var EvidenceIn Evidence

	err := EvidenceIn.SetClaims(
		mustBuildValidPlatformClaims(t, true),
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

func TestEvidence_sign_and_verify_realm_key_mismatch(t *testing.T) {
	rSigner := signerFromJWK(t, testRAK)
	pSigner := signerFromJWK(t, testIAK)

	var EvidenceIn Evidence

	err := EvidenceIn.SetClaims(
		mustBuildValidPlatformClaims(t, true),
		mustBuildValidCcaRealmClaims(t),
	)
	assert.NoError(t, err)

	// now set a different key from the one which is going to be used for
	// signing
	err = EvidenceIn.RealmClaims.SetPubKey(testAltRAKPubRaw)
	assert.NoError(t, err)

	ccaToken, err := EvidenceIn.Sign(pSigner, rSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("CCA evidence : %x\n", ccaToken)

	var EvidenceOut Evidence

	err = EvidenceOut.FromCBOR(ccaToken)
	assert.NoError(t, err, "CCA token decoding failed")

	mismatchedVerifier := pubKeyFromJWK(t, testIAK)

	err = EvidenceOut.Verify(mismatchedVerifier)
	assert.EqualError(t, err, "unable to verify realm token: verification error")
}

func TestEvidence_sign_unvalidated(t *testing.T) {
	rSigner := signerFromJWK(t, testRAK)
	pSigner := signerFromJWK(t, testIAK)

	testVectors := []struct {
		Platform platform.IClaims
		Realm    realm.IClaims
		Error    string
	}{
		{
			mustBuildValidPlatformClaims(t, true),
			mustBuildValidCcaRealmClaims(t),
			"",
		},
		{
			mustBuildValidPlatformClaims(t, true),
			nil,
			"",
		},
		{
			nil,
			nil,
			"",
		},
	}

	for _, tv := range testVectors {
		var EvidenceIn Evidence

		err := EvidenceIn.SetUnvalidatedClaims(tv.Platform, tv.Realm)
		assert.NoError(t, err)

		_, err = EvidenceIn.SignUnvalidated(pSigner, rSigner)
		if tv.Error == "" {
			assert.NoError(t, err, "signing failed")
		} else {
			assert.EqualError(t, err, tv.Error)
		}
	}
}

func TestEvidence_GetInstanceID_ok(t *testing.T) {
	var e Evidence

	err := e.SetClaims(
		mustBuildValidPlatformClaims(t, true),
		mustBuildValidCcaRealmClaims(t),
	)
	require.NoError(t, err)

	expected := &testInstID

	actual := e.GetInstanceID()
	assert.Equal(t, expected, actual)
}

func TestEvidence_GetImplementationID_ok(t *testing.T) {
	var e Evidence

	err := e.SetClaims(
		mustBuildValidPlatformClaims(t, true),
		mustBuildValidCcaRealmClaims(t),
	)
	require.NoError(t, err)

	expected := &testImplementationID

	actual := e.GetImplementationID()
	assert.Equal(t, expected, actual)
}

func TestEvidence_GetRealmPubKey_ok(t *testing.T) {
	var e Evidence

	err := e.SetClaims(
		mustBuildValidPlatformClaims(t, true),
		mustBuildValidCcaRealmClaims(t),
	)
	require.NoError(t, err)

	expected := &testRAKPubRaw

	actual := e.GetRealmPublicKey()
	assert.Equal(t, expected, actual)
}

func TestEvidence_MarshalJSON_fail(t *testing.T) {
	var e Evidence
	_, err := e.MarshalJSON()
	assert.EqualError(t, err, "invalid evidence")
}

func TestEvidence_MarshalJSON_ok(t *testing.T) {
	var e Evidence

	err := e.SetClaims(
		mustBuildValidPlatformClaims(t, true),
		mustBuildValidCcaRealmClaims(t),
	)
	require.NoError(t, err)

	expected := testCombinedClaimsJSON

	actual, err := e.MarshalJSON()
	assert.NoError(t, err)
	assert.JSONEq(t, expected, string(actual))
}

func TestEvidence_MarshalUnvalidatedJSON(t *testing.T) {
	var e Evidence

	err := e.SetClaims(
		mustBuildValidPlatformClaims(t, true),
		mustBuildValidCcaRealmClaims(t),
	)
	require.NoError(t, err)

	expected := testCombinedClaimsJSON

	actual, err := e.MarshalUnvalidatedJSON()
	assert.NoError(t, err)
	assert.JSONEq(t, expected, string(actual))

	var empty Evidence
	actual, err = empty.MarshalUnvalidatedJSON()
	assert.NoError(t, err)
	assert.JSONEq(t, "{}", string(actual))
}

func TestEvidence_UnmarshalJSON_ok(t *testing.T) {
	var e Evidence

	err := e.UnmarshalJSON([]byte(testCombinedClaimsJSON))
	assert.NoError(t, err)
}

func TestEvidence_UnmarshalJSON_missing_platform(t *testing.T) {
	var e Evidence

	expectedErr := "unmarshaling CCA claims: missing platform claims"

	err := e.UnmarshalJSON([]byte(testCombinedClaimsJSONMissingPlatform))
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_UnmarshalJSON_missing_realm(t *testing.T) {
	var e Evidence

	expectedErr := "unmarshaling CCA claims: missing realm claims"

	err := e.UnmarshalJSON([]byte(testCombinedClaimsJSONMissingRealm))
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_UnmarshalJSON_syntax_error(t *testing.T) {
	var e Evidence

	expectedErr := "unmarshaling CCA claims: unexpected end of JSON input"

	err := e.UnmarshalJSON(testNotJSON)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_UnmarshalUnvalidatedJSON(t *testing.T) {
	testVectors := []struct {
		Bytes []byte
		Error string
	}{
		{[]byte(testCombinedClaimsJSON), ""},
		{[]byte(testCombinedClaimsJSONMissingRealm), ""},
		{testNotJSON, "unmarshaling CCA claims: unexpected end of JSON input"},
	}

	for _, tv := range testVectors {
		var e Evidence
		err := e.UnmarshalUnvalidatedJSON(tv.Bytes)

		if tv.Error == "" {
			assert.NoError(t, err)
		} else {
			assert.EqualError(t, err, tv.Error)
		}
	}
}

func TestEvidence_JSON_roundtrip(t *testing.T) {
	var e Evidence

	err := e.SetClaims(
		mustBuildValidPlatformClaims(t, true),
		mustBuildValidCcaRealmClaims(t),
	)
	require.NoError(t, err)

	err = e.UnmarshalJSON([]byte(testCombinedClaimsJSON))
	assert.NoError(t, err)

	j, err := e.MarshalJSON()
	assert.NoError(t, err)

	assert.JSONEq(t, testCombinedClaimsJSON, string(j))
}

func TestEvidence_SetClaims_missing_realm_claims(t *testing.T) {
	var e Evidence

	err := e.SetClaims(
		mustBuildValidPlatformClaims(t, true),
		nil,
	)
	assert.EqualError(t, err, "nil claims supplied")
}

func TestEvidence_SetClaims_missing_platform_claims(t *testing.T) {
	var e Evidence

	err := e.SetClaims(
		nil,
		mustBuildValidCcaRealmClaims(t),
	)
	assert.EqualError(t, err, "nil claims supplied")
}

func TestEvidence_SetClaims_bind_failed(t *testing.T) {
	emptyRealmClaims := &realm.Claims{}
	emptyPlatformClaims := &platform.Claims{}

	expectedErr := "tokens binding failed: computing binder value: extracting RAK from the realm token: missing mandatory claim"

	var e Evidence

	err := e.SetClaims(emptyPlatformClaims, emptyRealmClaims)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_SetClaims_invalid_platform(t *testing.T) {
	emptyPlatformClaims := &platform.Claims{}

	expectedErr := "validation of cca-platform-claims failed: validating profile: missing mandatory claim"

	var e Evidence

	err := e.SetClaims(
		emptyPlatformClaims,
		mustBuildValidCcaRealmClaims(t),
	)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_SetClaims_invalid_realm(t *testing.T) {
	incompleteRealmClaims := &realm.Claims{}

	// just set the bare minimum to compute the binder
	err := incompleteRealmClaims.SetPubKey(testRAKPubRaw)
	require.NoError(t, err)

	err = incompleteRealmClaims.SetPubKeyHashAlgID("sha-256")
	require.NoError(t, err)

	expectedErr := "validation of cca-realm-claims failed: validating realm challenge claim: missing mandatory claim"

	var e Evidence

	err = e.SetClaims(
		mustBuildValidPlatformClaims(t, false),
		incompleteRealmClaims,
	)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_Sign_no_platform_claims(t *testing.T) {
	var (
		e      Evidence
		unused cose.Signer
	)

	expectedErr := "claims not set in evidence"

	_, err := e.Sign(unused, unused)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_Sign_invalid_signers(t *testing.T) {
	var (
		e       Evidence
		invalid cose.Signer
	)

	err := e.SetClaims(
		mustBuildValidPlatformClaims(t, false),
		mustBuildValidCcaRealmClaims(t),
	)
	require.NoError(t, err)

	expectedErr := "nil signer(s) supplied"

	_, err = e.Sign(invalid, invalid)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_Verify_no_message(t *testing.T) {
	var (
		empty  Evidence
		unused crypto.PublicKey
	)

	err := empty.Verify(unused)
	assert.EqualError(t, err, "no message found")
}

func TestEvidence_Verify_RMM(t *testing.T) {
	b := mustHexDecode(t, testRMMEvidence)

	var e Evidence
	err := e.FromCBOR(b)
	require.NoError(t, err)

	verifier := pubKeyFromJWK(t, testRMMCPAK)

	err = e.Verify(verifier)
	assert.NoError(t, err)
}

func TestEvidence_FromCBOR_wrong_top_level_tag(t *testing.T) {
	wrongCBORTag := []byte{
		0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x58, 0x1e, 0xa1, 0x19, 0x01,
		0x09, 0x78, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x61, 0x72,
		0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x73, 0x61, 0x2f, 0x33, 0x2e,
		0x30, 0x2e, 0x30, 0x44, 0xde, 0xad, 0xbe, 0xef,
	}

	expectedErr := `CBOR decoding of CCA evidence failed: cbor: wrong tag number for ccatoken.CBORCollection, got [18], expected [399]`

	var e Evidence

	err := e.FromCBOR(wrongCBORTag)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_FromCBOR_wrong_unwrapped_tokens(t *testing.T) {
	b := mustHexDecode(t, testBadUnwrappedTokens)

	expectedErr := `CBOR decoding of CCA evidence failed: cbor: cannot unmarshal byte string into Go struct field ccatoken.CBORCollection.44234 of type uint8`

	var e Evidence
	err := e.FromCBOR(b)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_FromCBOR_good_CCA_token(t *testing.T) {
	b := mustHexDecode(t, testGoodCCAToken)

	var e Evidence
	err := e.FromCBOR(b)
	assert.NoError(t, err)
}
