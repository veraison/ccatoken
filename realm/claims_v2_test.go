// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package realm

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/psatoken"
)

func mustBuildValidCcaRealmClaimsV2(t *testing.T) IClaims {
	c, err := NewClaimsWithProfile(ProfileNameV2)
	require.NoError(t, err)

	err = c.SetChallenge(testChallenge)
	require.NoError(t, err)

	err = c.SetPersonalizationValue(testPersonalizationVal)
	require.NoError(t, err)

	err = c.SetInitialMeasurement(testInitMeas)
	require.NoError(t, err)

	err = c.SetExtensibleMeasurements(testExtensibleMeas)
	require.NoError(t, err)

	err = c.SetHashAlgID(testHashAlgID)
	require.NoError(t, err)

	err = c.SetPubKey(TestAltRAKPubCOSE)
	require.NoError(t, err)

	err = c.SetPubKeyHashAlgID(testPubKeyHashAlgID)
	require.NoError(t, err)

	err = c.SetMECPolicy(testMECPolicy)
	require.NoError(t, err)

	return c
}

func Test_CcaRealmClaimsV2_ok(t *testing.T) {
	c := mustBuildValidCcaRealmClaimsV2(t)

	err := c.Validate()
	assert.NoError(t, err)
}

func Test_CcaClaimsV2_GetProfile_ok(t *testing.T) {
	c, err := NewClaimsWithProfile(ProfileNameV2)
	require.NoError(t, err)

	profile, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, ProfileNameV2, profile)
}

func Test_CcaRealmClaimsV2_SetMECPolicy_GetMECPolicy_Ok(t *testing.T) {
	c, err := NewClaimsWithProfile(ProfileNameV2)
	require.NoError(t, err)

	err = c.SetMECPolicy(MECPolicyPrivate)
	assert.NoError(t, err)
	v, err := c.GetMECPolicy()
	assert.NoError(t, err)
	assert.Equal(t, MECPolicyPrivate, v)

	err = c.SetMECPolicy(MECPolicyShared)
	assert.NoError(t, err)
	v, err = c.GetMECPolicy()
	assert.NoError(t, err)
	assert.Equal(t, MECPolicyShared, v)
}

func Test_CcaRealmClaimsV2_SetMECPolicy_nok(t *testing.T) {
	c, err := NewClaimsWithProfile(ProfileNameV2)
	require.NoError(t, err)

	err = c.SetMECPolicy(testNotMECPolicy)
	expectedErr := "wrong syntax: MEC policy MUST be 'private' or 'shared'"
	assert.EqualError(t, err, expectedErr)

	_, err = c.GetMECPolicy()
	assert.ErrorIs(t, err, psatoken.ErrMandatoryClaimMissing)

	c.(*ClaimsV2).MECPolicy = &testNotMECPolicy
	_, err = c.GetMECPolicy()
	assert.EqualError(t, err, expectedErr)
}

func Test_CcaRealmClaimsV2_MarshalCBOR_invalid(t *testing.T) {
	c, err := NewClaimsWithProfile(ProfileNameV2)
	require.NoError(t, err)

	expectedErr := `validating realm challenge claim: missing mandatory claim`

	_, err = ValidateAndEncodeClaimsToCBOR(c)

	assert.EqualError(t, err, expectedErr)
}

func Test_CcaRealmClaimsV2_MarshalCBOR_all_claims(t *testing.T) {
	c := mustBuildValidCcaRealmClaimsV2(t)
	expected := mustHexDecode(t, testEncodedCcaRealmClaimsV2All)

	actual, err := ValidateAndEncodeClaimsToCBOR(c)

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_CcaRealmClaimsV2_UnmarshalCBOR_ok(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaRealmClaimsV2All)

	c, err := DecodeAndValidateClaimsFromCBOR(buf)

	assert.NoError(t, err)

	expectedProfile := ProfileNameV2
	actualProfile, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, expectedProfile, actualProfile)

	expectedMECPolicy := testMECPolicy
	actualMECPolicy, err := c.GetMECPolicy()
	assert.NoError(t, err)
	assert.Equal(t, expectedMECPolicy, actualMECPolicy)

	expectedChallenge := testChallenge
	actualChallenge, err := c.GetChallenge()
	assert.NoError(t, err)
	assert.Equal(t, expectedChallenge, actualChallenge)

	expectedPersonalizationVal := testPersonalizationVal
	actualPersonalizationVal, err := c.GetPersonalizationValue()
	assert.NoError(t, err)
	assert.Equal(t, expectedPersonalizationVal, actualPersonalizationVal)

	expectedInitMeas := testInitMeas
	actualInitMeas, err := c.GetInitialMeasurement()
	assert.NoError(t, err)
	assert.Equal(t, expectedInitMeas, actualInitMeas)

	expectedExtensibleMeas := testExtensibleMeas
	actualExtensibleMeas, err := c.GetExtensibleMeasurements()
	assert.NoError(t, err)
	assert.Equal(t, expectedExtensibleMeas, actualExtensibleMeas)

	expectedHashAlgID := testHashAlgID
	actualHashAlgID, err := c.GetHashAlgID()
	assert.NoError(t, err)
	assert.Equal(t, expectedHashAlgID, actualHashAlgID)

	expectedPubKey := TestAltRAKPubCOSE
	actualPubKey, err := c.GetPubKey()
	assert.NoError(t, err)
	assert.Equal(t, expectedPubKey, actualPubKey)
}

func Test_CcaRealmClaimsV2_UnmarshalCBOR_negatives(t *testing.T) {
	negatives := []string{
		/* 0 */ testEncodedCcaRealmClaimsV2InvalidMECPolicy,
		/* 1 */ testEncodedCcaRealmClaimsV2MissingMECPolicy,
	}
	expectedErrors := []string{
		/* 0 */ "validating realm MEC policy claim: wrong syntax: MEC policy MUST be 'private' or 'shared'",
		/* 1 */ "validating realm MEC policy claim: missing mandatory claim",
	}
	for i, neg := range negatives {
		buf := mustHexDecode(t, neg)
		_, err := DecodeAndValidateClaimsFromCBOR(buf)
		assert.EqualError(t, err, expectedErrors[i], "CBOR negative %d failed", i)
	}
}

func Test_CcaRealmClaimsV2_MarshalJSON_ok(t *testing.T) {
	c := mustBuildValidCcaRealmClaimsV2(t)
	buf, err := os.ReadFile("testvectors/json/v2/test-cca-claims-all-valid.json")
	assert.NoError(t, err)
	expected := string(buf)

	actual, err := ValidateAndEncodeClaimsToJSON(c)
	assert.NoError(t, err)
	assert.JSONEq(t, expected, string(actual))
}

func Test_CcaRealmClaimsV2_UnmarshalJSON_ok(t *testing.T) {
	tvs := []string{
		/* 0 */ "testvectors/json/v2/test-cca-claims-all-valid.json",
		/* 1 */ "testvectors/json/v2/test-valid-shared-mec-policy.json",
	}
	for i, fn := range tvs {
		buf, err := os.ReadFile(fn)
		require.NoError(t, err)

		_, err = DecodeAndValidateClaimsFromJSON(buf)
		assert.NoError(t, err, "test vector %d failed", i)
	}

}

func Test_CcaRealmClaimsV2_UnmarshalJSON_negatives(t *testing.T) {
	tvs := []string{
		/* 0 */ "testvectors/json/v2/test-invalid-mec-policy.json",
		/* 1 */ "testvectors/json/v2/test-missing-mec-policy.json",
	}
	expectedErrors := []string{
		/* 0 */ "validating realm MEC policy claim: wrong syntax: MEC policy MUST be 'private' or 'shared'",
		/* 1 */ "validating realm MEC policy claim: missing mandatory claim",
	}
	for i, fn := range tvs {
		buf, err := os.ReadFile(fn)
		require.NoError(t, err)

		_, err = DecodeAndValidateClaimsFromJSON(buf)

		assert.EqualError(t, err, expectedErrors[i], "test vector %d failed", i)
	}
}
