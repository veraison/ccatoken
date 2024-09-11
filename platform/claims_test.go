// Copyright 2022-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testCCALifeCycleSecured = uint16(12288)
)

func mustBuildValidClaims(t *testing.T, includeOptional bool) IClaims {
	c := NewClaims()

	err := c.SetSecurityLifeCycle(testCCALifeCycleSecured)
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

func Test_NewClaims_ok(t *testing.T) {
	c := NewClaims()

	expected := ProfileName

	actual, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_Claims_Validate_all_claims(t *testing.T) {
	c := mustBuildValidClaims(t, true)

	err := c.Validate()
	assert.NoError(t, err)
}

func Test_Claims_Validate_mandatory_only_claims(t *testing.T) {
	c := mustBuildValidClaims(t, false)

	err := c.Validate()
	assert.NoError(t, err)
}

func Test_Claims_Set_NonValid_Claims(t *testing.T) {
	c := NewClaims()

	err := c.SetBootSeed([]byte("123"))
	expectedErr := "claim not in profile: boot seed"
	assert.EqualError(t, err, expectedErr)

	err = c.SetCertificationReference("testCertification")
	expectedErr = "claim not in profile: certification reference"
	assert.EqualError(t, err, expectedErr)

	err = c.SetClientID(1)
	expectedErr = "claim not in profile: client id"
	assert.EqualError(t, err, expectedErr)

	err = c.SetConfig([]byte{})
	expectedErr = "missing mandatory claim"
	assert.EqualError(t, err, expectedErr)

	err = c.SetHashAlgID("non existent")
	expectedErr = "wrong syntax: wrong syntax"
	assert.EqualError(t, err, expectedErr)

	err = c.SetHashAlgID("")
	expectedErr = "wrong syntax: empty string"
	assert.EqualError(t, err, expectedErr)
}

func Test_Claims_Get_NonValid_Claims(t *testing.T) {
	c := NewClaims()

	_, err := c.GetBootSeed()
	expectedErr := "claim not in profile: boot seed"
	assert.EqualError(t, err, expectedErr)

	_, err = c.GetCertificationReference()
	expectedErr = "claim not in profile: certification reference"
	assert.EqualError(t, err, expectedErr)

	_, err = c.GetClientID()
	expectedErr = "claim not in profile: client id"
	assert.EqualError(t, err, expectedErr)

}

func Test_CCAPlatform_Claims_MarshalCBOR_invalid(t *testing.T) {
	c := NewClaims()
	expectedErr := `validating security lifecycle: missing mandatory claim`

	_, err := ValidateAndEncodeClaimsToCBOR(c)

	assert.EqualError(t, err, expectedErr)
}

func Test_CCAPlatform_Claims_MarshalCBOR_all_claims(t *testing.T) {
	c := mustBuildValidClaims(t, true)
	expected := mustHexDecode(t, testEncodedCcaPlatformClaimsAll)

	actual, err := ValidateAndEncodeClaimsToCBOR(c)

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_CCAPlatform_Claims_MarshalCBOR_mandatory_only_claims(t *testing.T) {
	c := mustBuildValidClaims(t, false)
	expected := mustHexDecode(t, testEncodedCcaPlatformClaimsMandatoryOnly)

	actual, err := ValidateAndEncodeClaimsToCBOR(c)

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_CCAPlatform_UnmarshalCBOR_ok_mandatory_only(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaPlatformClaimsMandatoryOnly)

	c, err := DecodeAndValidateClaimsFromCBOR(buf)
	assert.NoError(t, err)

	// mandatory

	expectedProfile := ProfileName
	actualProfile, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, expectedProfile, actualProfile)

	expectedCCALifeCycle := testCCALifeCycleSecured
	actualCCALifeCycle, err := c.GetSecurityLifeCycle()
	assert.NoError(t, err)
	assert.Equal(t, expectedCCALifeCycle, actualCCALifeCycle)

	expectedImplID := testImplementationID
	actualImplID, err := c.GetImplID()
	assert.NoError(t, err)
	assert.Equal(t, expectedImplID, actualImplID)

	expectedNonce := testNonce
	actualNonce, err := c.GetNonce()
	assert.NoError(t, err)
	assert.Equal(t, expectedNonce, actualNonce)

	expectedInstID := testInstID
	actualInstID, err := c.GetInstID()
	assert.NoError(t, err)
	assert.Equal(t, expectedInstID, actualInstID)

	expectedSwComp := testSoftwareComponents
	actualSwComp, err := c.GetSoftwareComponents()
	assert.NoError(t, err)
	assert.Equal(t, expectedSwComp, actualSwComp)
}

func Test_CCAPlatform_Claims_UnmarshalCBOR_bad_input(t *testing.T) {
	buf := mustHexDecode(t, testNotCBOR)
	expectedErr := "unexpected EOF"

	_, err := DecodeAndValidateClaimsFromCBOR(buf)

	assert.EqualError(t, err, expectedErr)
}

func Test_CCAPlatform_Claims_UnmarshalCBOR_missing_mandatory_claim(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaPlatformClaimsMissingMandatoryNonce)
	expectedErr := "validating nonce: missing mandatory claim"

	_, err := DecodeAndValidateClaimsFromCBOR(buf)

	assert.EqualError(t, err, expectedErr)
}

func Test_CCAPlatform_Claims_UnmarshalCBOR_invalid_multi_nonce(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaPlatformClaimsInvalidMultiNonce)
	expectedErr := "validating nonce: wrong syntax: got 2 nonces, want 1"

	_, err := DecodeAndValidateClaimsFromCBOR(buf)

	assert.EqualError(t, err, expectedErr)
}

func Test_CCAPlatform_MarshalJSON_ok(t *testing.T) {
	c := mustBuildValidClaims(t, true)

	expected := `{
	   "cca-platform-profile": "tag:arm.com,2023:cca_platform#1.0.0",
	   "cca-platform-challenge":  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
	   "cca-platform-implementation-id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	   "cca-platform-instance-id": "AQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
	   "cca-platform-config": "AQID",
	   "cca-platform-lifecycle": 12288,
	   "cca-platform-sw-components": [
	   	  {
	   		"measurement-value": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
	   		"signer-id": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
	   	  }
	   	],
	   "cca-platform-service-indicator" : "https://veraison.example/v1/challenge-response",
	   "cca-platform-hash-algo-id": "sha-256"
	   }`
	actual, err := ValidateAndEncodeClaimsToJSON(c)
	assert.NoError(t, err)
	assert.JSONEq(t, expected, string(actual))
}

func Test_CCAPlatform_MarshalJSON_not_ok(t *testing.T) {
	c := &Claims{}
	expectedErr := `validating profile: missing mandatory claim`

	_, err := ValidateAndEncodeClaimsToCBOR(c)

	assert.EqualError(t, err, expectedErr)
}

func Test_CCAPlatform_UnmarshalJSON_ok(t *testing.T) {
	tv := `{
		"cca-platform-profile": "http://arm.com/CCA-SSD/1.0.0",
		"cca-platform-challenge":  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		"cca-platform-implementation-id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"cca-platform-instance-id": "AQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
		"cca-platform-config": "AQID",
		"cca-platform-lifecycle": 12288,
		"cca-platform-sw-components": [
			  {
				"measurement-value": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
				"signer-id": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
			  }
			],
		"cca-platform-service-indicator" : "https://veraison.example/v1/challenge-response",
		"cca-platform-hash-algo-id": "sha-256"
		}`

	_, err := DecodeAndValidateClaimsFromJSON([]byte(tv))

	assert.NoError(t, err)
}

func Test_CCAPlatform_UnmarshalJSON_invalid_json(t *testing.T) {
	tv := testNotJSON
	expectedErr := `unexpected end of JSON input`

	_, err := DecodeAndValidateClaimsFromJSON(tv)

	assert.EqualError(t, err, expectedErr)
}

func Test_CCAPlatform_UnmarshalJSON_negatives(t *testing.T) {
	tvs := []string{
		/* 0 */ "testvectors/json/test-invalid-profile.json",
		/* 1 */ "testvectors/json/test-vsi-invalid-empty.json",
		/* 2 */ "testvectors/json/test-implementation-id-invalid-long.json",
		/* 3 */ "testvectors/json/test-implementation-id-invalid-missing.json",
		/* 4 */ "testvectors/json/test-no-sw-components.json",
		/* 5 */ "testvectors/json/test-sw-components-invalid-combo.json",
		/* 6 */ "testvectors/json/test-hash-algid-invalid.json",
		/* 7 */ "testvectors/json/test-no-sw-components.json",
		/* 8 */ "testvectors/json/test-lifecycle-invalid.json",
		/* 9 */ "testvectors/json/test-sw-components-invalid-missing.json",
		/* 10 */ "testvectors/json/test-nonce-invalid.json",
		/* 11 */ "testvectors/json/test-instance-id-missing.json",
		/* 12 */ "testvectors/json/test-instance-id-invalid.json",
		/* 13 */ "testvectors/json/test-config-missing.json",
		/* 14 */ "testvectors/json/test-hash-algid-missing.json",
		/* 15 */ "testvectors/json/test-invalid-psa-claims.json",
	}

	for i, fn := range tvs {
		buf, err := os.ReadFile(fn)
		require.NoError(t, err)

		_, err = DecodeAndValidateClaimsFromJSON(buf)

		assert.Error(t, err, "test vector %d failed", i)
	}
}

func Test_DecodeClaims_CCAPlatform_ok(t *testing.T) {
	tvs := []string{
		testEncodedCcaPlatformClaimsAll,
		testEncodedCcaPlatformLegacyClaimsAll,
		testEncodedCcaPlatformClaimsMandatoryOnly,
		testEncodedCcaPlatformLegacyClaimsMandatoryOnly,
	}

	for _, tv := range tvs {
		buf := mustHexDecode(t, tv)
		_, err := DecodeAndValidateClaimsFromCBOR(buf)

		assert.NoError(t, err)
	}
}

func Test_DecodeClaims_CCAPlatform_failure(t *testing.T) {
	tvs := []string{
		testEncodedCcaPlatformClaimsMissingMandatoryNonce,
	}

	for _, tv := range tvs {
		buf := mustHexDecode(t, tv)
		_, err := DecodeAndValidateClaimsFromCBOR(buf)

		expectedError := `validating nonce: missing mandatory claim`

		assert.EqualError(t, err, expectedError)
	}
}

func Test_DecodeUnvalidatedCCAClaims(t *testing.T) {
	type TestVector struct {
		Input    string
		Expected interface{}
	}

	tvs := []TestVector{
		{testEncodedCcaPlatformClaimsMissingMandatoryNonce, &Claims{}},
	}

	for _, tv := range tvs {
		buf := mustHexDecode(t, tv.Input)
		v, err := DecodeClaimsFromCBOR(buf)

		assert.NoError(t, err)
		assert.IsType(t, tv.Expected, v)
	}
}

func Test_NewClaims_CcaPlatform_ok(t *testing.T) {
	c := NewClaims()

	p, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, ProfileName, p)
}

func Test_DecodeJSONClaims_CcaPlatform(t *testing.T) {
	buf, err := os.ReadFile("testvectors/json/test-token-valid-full.json")
	require.NoError(t, err)

	c, err := DecodeAndValidateClaimsFromJSON(buf)
	assert.NoError(t, err)
	actualProfile, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, LegacyProfileName, actualProfile)
}

func Test_DecodeUnvalidatedJSONCCAClaims(t *testing.T) {
	type TestVector struct {
		Path     string
		Expected interface{}
	}
	tvs := []TestVector{
		// valid
		{"testvectors/json/test-token-valid-full.json", &Claims{}},

		// invalid
		{"testvectors/json/test-no-sw-components.json", &Claims{}},
		{"testvectors/json/test-invalid-psa-claims.json", &Claims{}},
	}

	for _, tv := range tvs {
		buf, err := os.ReadFile(tv.Path)
		require.NoError(t, err)

		v, err := DecodeClaimsFromJSON(buf)

		require.NoError(t, err)
		assert.IsType(t, tv.Expected, v)
	}
}

func Test_CcaLifeCycleState(t *testing.T) {
	type TestVector struct {
		Val  uint16
		Text string
	}

	validTestVectors := []TestVector{
		{0x0000, "unknown"},
		{0x00a7, "unknown"},
		{0x00ff, "unknown"},
		{0x1010, "assembly-and-test"},
		{0x2001, "cca-platform-rot-provisioning"},
		{0x20ff, "cca-platform-rot-provisioning"},
		{0x3000, "secured"},
		{0x3090, "secured"},
		{0x30ff, "secured"},
		{0x4020, "non-cca-platform-rot-debug"},
		{0x5000, "recoverable-cca-platform-rot-debug"},
		{0x50af, "recoverable-cca-platform-rot-debug"},
		{0x6001, "decommissioned"},
		{0x60ff, "decommissioned"},
	}

	for _, tv := range validTestVectors {
		state := LifeCycleToState(tv.Val)

		assert.True(t, state.IsValid())
		assert.Equal(t, tv.Text, state.String())
	}

	invalidTestVectors := []TestVector{
		{0x1500, "doesn't matter"},
		{0x6100, "won't be used"},
		{0x8a47, "who cares?"},
		{0xffff, "pineapples"},
	}

	for _, tv := range invalidTestVectors {
		state := LifeCycleToState(tv.Val)

		assert.False(t, state.IsValid())
		assert.Equal(t, "invalid", state.String())
	}
}

func Test_ToUnvalidated(t *testing.T) {
	c := NewClaims()

	_, err := EncodeClaimsToCBOR(c)
	assert.NoError(t, err)

	_, err = EncodeClaimsToJSON(c)
	assert.NoError(t, err)
}
