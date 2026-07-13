// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testClientID = int32(1)
)

func mustBuildValidClaimsV2(t *testing.T, includeOptional bool) *ClaimsV2 {
	ic, err := NewClaimsWithProfile(ProfileNameV2)
	require.NoError(t, err)

	c, ok := ic.(*ClaimsV2)
	require.True(t, ok)

	err = c.SetClientID(testClientID)
	require.NoError(t, err)

	err = c.SetSecurityLifeCycle(testCCALifeCycleSecured)
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

		err = c.SetManufacturingConfig(testConfig)
		require.NoError(t, err)

		tbbRoTPKItem := TBBRoTPKItem{}
		err = tbbRoTPKItem.SetName("DM")
		require.NoError(t, err)

		err = tbbRoTPKItem.SetActiveRoTPKArray(0)
		require.NoError(t, err)

		err = tbbRoTPKItem.SetIndex(0)
		require.NoError(t, err)

		err = tbbRoTPKItem.SetHash(testMeasurementValue)
		require.NoError(t, err)

		err = c.SetTBBRoTPK([]ITBBRoTPKItem{&tbbRoTPKItem})
		require.NoError(t, err)

		err = c.SetPeerSigners(testSignerID)
		require.NoError(t, err)
	}

	return c
}

func Test_NewClaimsV2_ok(t *testing.T) {
	c, err := NewClaimsWithProfile(ProfileNameV2)
	require.NoError(t, err)

	c, ok := c.(*ClaimsV2)
	require.True(t, ok)

	actual, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, ProfileNameV2, actual)
}

func Test_ClaimsV2_Validate_mandatory_only_claims(t *testing.T) {
	c := mustBuildValidClaimsV2(t, false)

	err := c.Validate()
	assert.NoError(t, err)
}

func Test_ClaimsV2_Validate_all_new_claims(t *testing.T) {
	c := mustBuildValidClaimsV2(t, true)

	err := c.Validate()
	assert.NoError(t, err)
}

func Test_ClaimsV2_Validate_new_claim_failures(t *testing.T) {
	c := mustBuildValidClaimsV2(t, false)
	c.ClientID = nil
	assert.EqualError(t, c.Validate(), "validating client id: missing mandatory claim")

	c = mustBuildValidClaimsV2(t, true)
	emptyManufacturingConfig := []byte{}
	c.ManufacturingConfig = &emptyManufacturingConfig
	assert.EqualError(t, c.Validate(), "validating platform manufacturing config: wrong syntax: manufacturing config")

	c = mustBuildValidClaimsV2(t, true)
	c.TBBRoTPK = &TBBRoTPKItems{values: []*TBBRoTPKItem{{}}}
	assert.EqualError(t, c.Validate(), "validating platform TBB ROTPK: failed at index 0: name: missing mandatory field")

	c = mustBuildValidClaimsV2(t, true)
	partialTBBRoTPKItem := TBBRoTPKItem{}
	err := partialTBBRoTPKItem.SetName("DM")
	require.NoError(t, err)
	err = partialTBBRoTPKItem.SetActiveRoTPKArray(0)
	require.NoError(t, err)
	err = partialTBBRoTPKItem.SetIndex(0)
	require.NoError(t, err)
	c.TBBRoTPK = &TBBRoTPKItems{values: []*TBBRoTPKItem{&partialTBBRoTPKItem}}
	assert.EqualError(t, c.Validate(), "validating platform TBB ROTPK: failed at index 0: hash: missing mandatory field")

	c = mustBuildValidClaimsV2(t, true)
	badPeerSigners := []byte{}
	c.PeerSigners = &badPeerSigners
	assert.EqualError(t, c.Validate(), "validating platform peer signers: wrong syntax: peer signers")
}

func Test_ClaimsV2_UnmarshalJSON_ok(t *testing.T) {
	buf, err := os.ReadFile("testvectors/json_v2/test-token-valid-full.json")
	require.NoError(t, err)

	_, err = DecodeAndValidateClaimsFromJSON(buf)

	assert.NoError(t, err)
}

func Test_ClaimsV2_UnmarshalJSON_negatives(t *testing.T) {
	tvs := []string{
		/* 0 */ "testvectors/json_v2/test-client-id-missing.json",
		/* 1 */ "testvectors/json_v2/test-client-id-invalid.json",
		/* 2 */ "testvectors/json_v2/test-manufacturing-config-invalid.json",
		/* 3 */ "testvectors/json_v2/test-peer-signers-invalid.json",
		/* 4 */ "testvectors/json_v2/test-tbb-rotpk-invalid-1.json",
		/* 5 */ "testvectors/json_v2/test-tbb-rotpk-invalid-2.json",
		/* 6 */ "testvectors/json_v2/test-tbb-rotpk-invalid-3.json",
	}

	for i, fn := range tvs {
		buf, err := os.ReadFile(fn)
		require.NoError(t, err)

		_, err = DecodeAndValidateClaimsFromJSON(buf)

		assert.Error(t, err, "test vector %d failed", i)
	}
}

func Test_CCAPlatform_ClaimsV2_MarshalCBOR_all_claims(t *testing.T) {
	c := mustBuildValidClaimsV2(t, true)
	expected := mustHexDecode(t, testEncodedCcaPlatformClaimsV2All)

	actual, err := ValidateAndEncodeClaimsToCBOR(c)

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_CCAPlatform_ClaimsV2_MarshalCBOR_mandatory_only(t *testing.T) {
	c := mustBuildValidClaimsV2(t, false)
	expected := mustHexDecode(t, testEncodedCcaPlatformClaimsV2MandatoryOnly)

	actual, err := ValidateAndEncodeClaimsToCBOR(c)

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_CCAPlatform_ClaimsV2_MarshalCBOR_invalid(t *testing.T) {
	c := mustBuildValidClaimsV2(t, false)
	c.ClientID = nil

	_, err := ValidateAndEncodeClaimsToCBOR(c)

	assert.EqualError(t, err, "validating client id: missing mandatory claim")
}

func Test_CCAPlatform_ClaimsV2_MarshalJSON_all_claims(t *testing.T) {
	c := mustBuildValidClaimsV2(t, true)
	expected, err := os.ReadFile("testvectors/json_v2/test-token-valid-full.json")
	require.NoError(t, err)

	actual, err := ValidateAndEncodeClaimsToJSON(c)

	assert.NoError(t, err)
	assert.JSONEq(t, string(expected), string(actual))
}

func Test_CCAPlatform_ClaimsV2_MarshalJSON_invalid(t *testing.T) {
	c := mustBuildValidClaimsV2(t, false)
	c.ClientID = nil

	_, err := ValidateAndEncodeClaimsToJSON(c)

	assert.EqualError(t, err, "validating client id: missing mandatory claim")
}

func Test_CCAPlatform_ClaimsV2_UnmarshalCBOR_mandatory_only(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaPlatformClaimsV2MandatoryOnly)

	_, err := DecodeAndValidateClaimsFromCBOR(buf)

	assert.NoError(t, err)
}

func Test_CCAPlatform_ClaimsV2_UnmarshalCBOR_missing_client_id(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaPlatformClaimsV2MissingClientId)

	_, err := DecodeAndValidateClaimsFromCBOR(buf)

	assert.EqualError(t, err, "validating client id: missing mandatory claim")
}

func Test_CCAPlatform_ClaimsV2_UnmarshalCBOR_invalid_manufacturing_config(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaPlatformClaimsV2InvalidMfgConfig)

	_, err := DecodeAndValidateClaimsFromCBOR(buf)

	assert.EqualError(t, err, "validating platform manufacturing config: wrong syntax: manufacturing config")
}

func Test_CCAPlatform_ClaimsV2_UnmarshalCBOR_invalid_tbb_rotpk_hash_length(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaPlatformClaimsV2InvalidTbbRotpkHashLength)

	_, err := DecodeAndValidateClaimsFromCBOR(buf)

	assert.EqualError(t, err, "validating platform TBB ROTPK: failed at index 0: hash: wrong syntax: length 34 (hash MUST be 32, 48 or 64 bytes)")
}
