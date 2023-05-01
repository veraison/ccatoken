package ccatoken

import (
	"crypto"
	"fmt"
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
	"github.com/veraison/psatoken"
)

func mustBuildValidCcaPlatformClaims(t *testing.T, includeOptional bool) psatoken.IClaims {
	c, err := psatoken.NewClaims(testCcaProfile)
	require.NoError(t, err)

	err = c.SetSecurityLifeCycle(testPlatformLifecycleSecured)
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

func Test_CcaPlatform_FromCBOR_ok_mandatory_RMM(t *testing.T) {
	buf := []byte{
		0xD2, 0x84, 0x44, 0xA1, 0x01, 0x38, 0x22, 0xA0,
		0x59, 0x02, 0x33, 0xA9, 0x19, 0x01, 0x09, 0x78,
		0x1C, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F,
		0x61, 0x72, 0x6D, 0x2E, 0x63, 0x6F, 0x6D, 0x2F,
		0x43, 0x43, 0x41, 0x2D, 0x53, 0x53, 0x44, 0x2F,
		0x31, 0x2E, 0x30, 0x2E, 0x30, 0x0A, 0x58, 0x20,
		0xB5, 0x97, 0x3C, 0xB6, 0x8B, 0xAA, 0x9F, 0xC5,
		0x55, 0x58, 0x78, 0x6B, 0x7E, 0xC6, 0x7F, 0x69,
		0xE4, 0x0D, 0xF5, 0xBA, 0x5A, 0xA9, 0x21, 0xCD,
		0x0C, 0x27, 0xF4, 0x05, 0x87, 0xA0, 0x11, 0xEA,
		0x19, 0x09, 0x5C, 0x58, 0x20, 0x7F, 0x45, 0x4C,
		0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x3E,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x50, 0x58, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x01, 0x00,
		0x58, 0x21, 0x01, 0x07, 0x06, 0x05, 0x04, 0x03,
		0x02, 0x01, 0x00, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B,
		0x0A, 0x09, 0x08, 0x17, 0x16, 0x15, 0x14, 0x13,
		0x12, 0x11, 0x10, 0x1F, 0x1E, 0x1D, 0x1C, 0x1B,
		0x1A, 0x19, 0x18, 0x19, 0x09, 0x61, 0x58, 0x21,
		0x01, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		0x00, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09,
		0x08, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
		0x10, 0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19,
		0x18, 0x19, 0x09, 0x5B, 0x19, 0x30, 0x03, 0x19,
		0x09, 0x62, 0x67, 0x73, 0x68, 0x61, 0x2D, 0x32,
		0x35, 0x36, 0x19, 0x09, 0x5F, 0x84, 0xA5, 0x01,
		0x62, 0x42, 0x4C, 0x05, 0x58, 0x20, 0x07, 0x06,
		0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x0F, 0x0E,
		0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x17, 0x16,
		0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x1F, 0x1E,
		0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x04, 0x65,
		0x33, 0x2E, 0x34, 0x2E, 0x32, 0x02, 0x58, 0x20,
		0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
		0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
		0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
		0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18,
		0x06, 0x74, 0x54, 0x46, 0x2D, 0x4D, 0x5F, 0x53,
		0x48, 0x41, 0x32, 0x35, 0x36, 0x4D, 0x65, 0x6D,
		0x50, 0x72, 0x65, 0x58, 0x49, 0x50, 0xA4, 0x01,
		0x62, 0x4D, 0x31, 0x05, 0x58, 0x20, 0x07, 0x06,
		0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x0F, 0x0E,
		0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x17, 0x16,
		0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x1F, 0x1E,
		0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x04, 0x63,
		0x31, 0x2E, 0x32, 0x02, 0x58, 0x20, 0x07, 0x06,
		0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x0F, 0x0E,
		0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x17, 0x16,
		0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x1F, 0x1E,
		0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0xA4, 0x01,
		0x62, 0x4D, 0x32, 0x05, 0x58, 0x20, 0x07, 0x06,
		0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x0F, 0x0E,
		0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x17, 0x16,
		0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x1F, 0x1E,
		0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x04, 0x65,
		0x31, 0x2E, 0x32, 0x2E, 0x33, 0x02, 0x58, 0x20,
		0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
		0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
		0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
		0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18,
		0xA4, 0x01, 0x62, 0x4D, 0x33, 0x05, 0x58, 0x20,
		0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
		0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
		0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
		0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18,
		0x04, 0x61, 0x31, 0x02, 0x58, 0x20, 0x07, 0x06,
		0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x0F, 0x0E,
		0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x17, 0x16,
		0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x1F, 0x1E,
		0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x19, 0x09,
		0x60, 0x6C, 0x77, 0x68, 0x61, 0x74, 0x65, 0x76,
		0x65, 0x72, 0x2E, 0x63, 0x6F, 0x6D, 0x58, 0x60,
		0xE6, 0xB6, 0x38, 0x4F, 0xAE, 0x3F, 0x6E, 0x67,
		0xF5, 0xD4, 0x97, 0x4B, 0x3F, 0xFD, 0x0A, 0xFA,
		0x1D, 0xF0, 0x2F, 0x73, 0xB8, 0xFF, 0x5F, 0x02,
		0xC0, 0x0F, 0x40, 0xAC, 0xF3, 0xA2, 0x9D, 0xB5,
		0x31, 0x50, 0x16, 0x4F, 0xFA, 0x34, 0x3D, 0x0E,
		0xAF, 0xE0, 0xD0, 0xD1, 0x6C, 0xF0, 0x9D, 0xC1,
		0x01, 0x42, 0xA2, 0x3C, 0xCE, 0xD4, 0x4A, 0x59,
		0xDC, 0x29, 0x0A, 0x30, 0x93, 0x5F, 0xB4, 0x98,
		0x61, 0xBA, 0xE3, 0x91, 0x22, 0x95, 0x24, 0xF4,
		0xAE, 0x47, 0x93, 0xD3, 0x84, 0xA3, 0x76, 0xD0,
		0xC1, 0x26, 0x96, 0x53, 0xA3, 0x60, 0x3F, 0x6C,
		0x75, 0x96, 0x90, 0x6A, 0xF9, 0x4E, 0xDA, 0x30,
	}

	// decode platform
	pSign1 := cose.NewSign1Message()

	err := pSign1.UnmarshalCBOR(buf)
	require.NoError(t, err)

	PlatformClaims, err := psatoken.DecodeClaims(pSign1.Payload)
	require.NoError(t, err)
	jd, err := PlatformClaims.ToJSON()
	err = os.WriteFile("testvectors/json/tf-rmm.json", jd, (os.ModeAppend | 0x3FF))

}
func TestEvidenceCCA(t *testing.T) {
	var EvidenceIn Evidence

	tokenBytes, err := os.ReadFile("testvectors/tf-rmm/cca-sha256.cbor")
	require.NoError(t, err)
	err = EvidenceIn.FromCBOR(tokenBytes)
	require.NoError(t, err)
	tokenBytes, err = EvidenceIn.MarshalJSON()
	err = os.WriteFile("testvectors/tf-rmm/cca-sha256.json", tokenBytes, fs.ModeAppend)
	require.NoError(t, err)

	tokenBytes, err = os.ReadFile("testvectors/cbor/tf-rmm-original-fvp.cbor")
	require.NoError(t, err)
	err = EvidenceIn.FromCBOR(tokenBytes)
	require.NoError(t, err)
	tokenBytes, err = EvidenceIn.MarshalJSON()
	err = os.WriteFile("testvectors/json/tf-rmm-original-fvp.json", tokenBytes, (fs.ModeAppend | 0x3FF))
	require.NoError(t, err)

	tokenBytes, err = os.ReadFile("testvectors/tf-rmm/cca-sha512.cbor")
	require.NoError(t, err)
	err = EvidenceIn.FromCBOR(tokenBytes)
	require.NoError(t, err)
	tokenBytes, err = EvidenceIn.MarshalJSON()
	err = os.WriteFile("testvectors/tf-rmm/cca-sha512.json", tokenBytes, fs.ModeAppend)
	require.NoError(t, err)

	tokenBytes, err = os.ReadFile("testvectors/tf-rmm/cca_token.cbor")
	require.NoError(t, err)
	err = EvidenceIn.FromCBOR(tokenBytes)
	require.NoError(t, err)
	tokenBytes, err = EvidenceIn.MarshalJSON()
	err = os.WriteFile("testvectors/tf-rmm/cca-token.json", tokenBytes, fs.ModeAppend)
	require.NoError(t, err)
}
func TestEvidence_sign_and_verify_ok(t *testing.T) {
	rSigner := signerFromJWK(t, testRAK)
	pSigner := signerFromJWK(t, testIAK)

	var EvidenceIn Evidence

	err := EvidenceIn.SetClaims(
		mustBuildValidCcaPlatformClaims(t, true),
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
		mustBuildValidCcaPlatformClaims(t, true),
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
		mustBuildValidCcaPlatformClaims(t, true),
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
		mustBuildValidCcaPlatformClaims(t, true),
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
		Platform psatoken.IClaims
		Realm    IClaims
		Error    string
	}{
		{
			mustBuildValidCcaPlatformClaims(t, true),
			mustBuildValidCcaRealmClaims(t),
			"",
		},
		{
			mustBuildValidCcaPlatformClaims(t, true),
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
		mustBuildValidCcaPlatformClaims(t, true),
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
		mustBuildValidCcaPlatformClaims(t, true),
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
		mustBuildValidCcaPlatformClaims(t, true),
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
		mustBuildValidCcaPlatformClaims(t, true),
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
		mustBuildValidCcaPlatformClaims(t, true),
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
		mustBuildValidCcaPlatformClaims(t, true),
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
		mustBuildValidCcaPlatformClaims(t, true),
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
	emptyRealmClaims := &RealmClaims{}
	emptyPlatformClaims := &psatoken.CcaPlatformClaims{}

	expectedErr := "tokens binding failed: computing binder value: extracting RAK from the realm token: missing mandatory claim"

	var e Evidence

	err := e.SetClaims(emptyPlatformClaims, emptyRealmClaims)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_SetClaims_invalid_platform(t *testing.T) {
	emptyPlatformClaims := &psatoken.CcaPlatformClaims{}

	expectedErr := "validation of cca-platform-claims failed: validating profile: missing mandatory claim"

	var e Evidence

	err := e.SetClaims(
		emptyPlatformClaims,
		mustBuildValidCcaRealmClaims(t),
	)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_SetClaims_invalid_realm(t *testing.T) {
	incompleteRealmClaims := &RealmClaims{}

	// just set the bare minimum to compute the binder
	err := incompleteRealmClaims.SetPubKey(testRAKPubRaw)
	require.NoError(t, err)

	err = incompleteRealmClaims.SetPubKeyHashAlgID("sha-256")
	require.NoError(t, err)

	expectedErr := "validation of cca-realm-claims failed: validating cca-realm-challenge claim: missing mandatory claim"

	var e Evidence

	err = e.SetClaims(
		mustBuildValidCcaPlatformClaims(t, false),
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
		mustBuildValidCcaPlatformClaims(t, false),
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
