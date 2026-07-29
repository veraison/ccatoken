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
	testClientID                 = int32(1)
	testBadClientID              = int32(0)
	testTBBRoTPKName             = "DM"
	testTBBRoTPKActiveArrayIndex = int32(0)
	testTBBRoTPKIndex            = int32(0)
	testTBBRoTPKHash             = []byte{
		7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7,
	}
	testPeerSigners = []byte{5, 5, 5, 5, 5}
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
		err = tbbRoTPKItem.SetName(testTBBRoTPKName)
		require.NoError(t, err)

		err = tbbRoTPKItem.SetActiveRoTPKArray(testTBBRoTPKActiveArrayIndex)
		require.NoError(t, err)

		err = tbbRoTPKItem.SetIndex(testTBBRoTPKIndex)
		require.NoError(t, err)

		err = tbbRoTPKItem.SetHash(testTBBRoTPKHash)
		require.NoError(t, err)

		err = c.SetTBBRoTPK([]*TBBRoTPKItem{&tbbRoTPKItem})
		require.NoError(t, err)

		err = c.SetPeerSigners(testPeerSigners)
		require.NoError(t, err)
	}

	return c
}

func Test_ClaimsV2_NewClaimsWithProfile_ok(t *testing.T) {
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

	err := c.SetClientID(testBadClientID)
	assert.EqualError(t, err, "wrong syntax: client id MUST be 1")

	c = mustBuildValidClaimsV2(t, true)
	emptyManufacturingConfig := []byte{}
	c.ManufacturingConfig = &emptyManufacturingConfig
	assert.EqualError(t, c.Validate(), "validating platform manufacturing config: wrong syntax: manufacturing config")

	c = mustBuildValidClaimsV2(t, true)
	var tbbRotPk TBBRoTPKItems
	tbbRotPk = []*TBBRoTPKItem{{}}
	c.TBBRoTPK = &tbbRotPk
	assert.EqualError(t, c.Validate(), "validating platform TBB ROTPK: failed at index 0: name: missing mandatory field")

	c = mustBuildValidClaimsV2(t, true)
	partialTBBRoTPKItem := TBBRoTPKItem{}
	err = partialTBBRoTPKItem.SetName(testTBBRoTPKName)
	require.NoError(t, err)
	err = partialTBBRoTPKItem.SetActiveRoTPKArray(testTBBRoTPKActiveArrayIndex)
	require.NoError(t, err)
	err = partialTBBRoTPKItem.SetIndex(testTBBRoTPKIndex)
	require.NoError(t, err)

	tbbRotPk = []*TBBRoTPKItem{&partialTBBRoTPKItem}
	c.TBBRoTPK = &tbbRotPk
	assert.EqualError(t, c.Validate(), "validating platform TBB ROTPK: failed at index 0: hash: missing mandatory field")

	c = mustBuildValidClaimsV2(t, true)
	badPeerSigners := []byte{}
	c.PeerSigners = &badPeerSigners
	assert.EqualError(t, c.Validate(), "validating platform peer signers: wrong syntax: peer signers")
}

func Test_ClaimsV2_UnmarshalJSON_ok(t *testing.T) {
	buf, err := os.ReadFile("testvectors/json/v2/test-token-valid-full.json")
	require.NoError(t, err)

	c, err := DecodeAndValidateClaimsFromJSON(buf)

	require.NoError(t, err)
	assertDecodedClaimsV2(t, c, true)
}

func Test_ClaimsV2_UnmarshalJSON_invalid(t *testing.T) {
	_, err := DecodeAndValidateClaimsFromJSON(testNotJSON)

	assert.EqualError(t, err, "unexpected end of JSON input")
}

func Test_ClaimsV2_UnmarshalJSON_negatives(t *testing.T) {
	tvs := []string{
		/* 0 */ "testvectors/json/v2/test-client-id-missing.json",
		/* 1 */ "testvectors/json/v2/test-client-id-invalid.json",
		/* 2 */ "testvectors/json/v2/test-manufacturing-config-invalid.json",
		/* 3 */ "testvectors/json/v2/test-peer-signers-invalid.json",
		/* 4 */ "testvectors/json/v2/test-tbb-rotpk-invalid-bad-hash.json",
		/* 5 */ "testvectors/json/v2/test-tbb-rotpk-invalid-bad-name.json",
		/* 6 */ "testvectors/json/v2/test-tbb-rotpk-invalid-no-active-arr.json",
	}

	expectedErrors := []string{
		/* 0 */ "validating client id: missing mandatory claim",
		/* 1 */ "validating client id: wrong syntax: client id MUST be 1",
		/* 2 */ "validating platform manufacturing config: wrong syntax: manufacturing config",
		/* 3 */ "validating platform peer signers: wrong syntax: peer signers",
		/* 4 */ "validating platform TBB ROTPK: failed at index 0: hash: wrong syntax: length 33 (hash MUST be 32, 48 or 64 bytes)",
		/* 5 */ "validating platform TBB ROTPK: failed at index 0: name: invalid name: Abc123, must be 'CM' or 'DM'",
		/* 6 */ "validating platform TBB ROTPK: failed at index 0: active array index: missing mandatory field",
	}

	for i, fn := range tvs {
		buf, err := os.ReadFile(fn)
		require.NoError(t, err)

		_, err = DecodeAndValidateClaimsFromJSON(buf)

		assert.EqualError(t, err, expectedErrors[i])
	}
}

func Test_CCAPlatform_ClaimsV2_MarshalJSON_all_claims(t *testing.T) {
	c := mustBuildValidClaimsV2(t, true)
	expected, err := os.ReadFile("testvectors/json/v2/test-token-valid-full.json")
	require.NoError(t, err)

	actual, err := ValidateAndEncodeClaimsToJSON(c)

	assert.NoError(t, err)
	assert.JSONEq(t, string(expected), string(actual))
}

func Test_CCAPlatform_ClaimsV2_MarshalJSON_mandatory_only(t *testing.T) {
	c := mustBuildValidClaimsV2(t, false)
	expected, err := os.ReadFile("testvectors/json/v2/test-token-valid-mandatory-only.json")
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

	c, err := DecodeAndValidateClaimsFromCBOR(buf)

	require.NoError(t, err)
	assertDecodedClaimsV2(t, c, false)
}

func Test_CCAPlatform_ClaimsV2_UnmarshalCBOR_all_claims(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaPlatformClaimsV2All)

	c, err := DecodeAndValidateClaimsFromCBOR(buf)

	require.NoError(t, err)
	assertDecodedClaimsV2(t, c, true)
}

func Test_CCAPlatform_ClaimsV2_UnmarshalCBOR_invalid(t *testing.T) {
	buf := mustHexDecode(t, testNotCBOR)

	_, err := DecodeAndValidateClaimsFromCBOR(buf)

	assert.EqualError(t, err, "unexpected EOF")
}

func Test_CCAPlatform_ClaimsV2_UnmarshalCBOR_missing_client_id(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaPlatformClaimsV2MissingClientID)

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

func Test_ClaimsV2_Codec_roundtrip(t *testing.T) {
	for _, includeOptional := range []bool{false, true} {
		c := mustBuildValidClaimsV2(t, includeOptional)

		t.Run("CBOR", func(t *testing.T) {
			encoded, err := ValidateAndEncodeClaimsToCBOR(c)
			require.NoError(t, err)

			decoded, err := DecodeAndValidateClaimsFromCBOR(encoded)
			require.NoError(t, err)
			assertDecodedClaimsV2(t, decoded, includeOptional)
		})

		t.Run("JSON", func(t *testing.T) {
			encoded, err := ValidateAndEncodeClaimsToJSON(c)
			require.NoError(t, err)

			decoded, err := DecodeAndValidateClaimsFromJSON(encoded)
			require.NoError(t, err)
			assertDecodedClaimsV2(t, decoded, includeOptional)
		})
	}
}

func assertDecodedClaimsV2(t *testing.T, c IClaims, includeOptional bool) {
	t.Helper()

	_, ok := c.(*ClaimsV2)
	require.True(t, ok)

	profile, err := c.GetProfile()
	require.NoError(t, err)
	assert.Equal(t, ProfileNameV2, profile)

	clientID, err := c.GetClientID()
	require.NoError(t, err)
	assert.Equal(t, testClientID, clientID)

	lifecycle, err := c.GetSecurityLifeCycle()
	require.NoError(t, err)
	assert.Equal(t, testCCALifeCycleSecured, lifecycle)

	implementationID, err := c.GetImplID()
	require.NoError(t, err)
	assert.Equal(t, testImplementationID, implementationID)

	nonce, err := c.GetNonce()
	require.NoError(t, err)
	assert.Equal(t, testNonce, nonce)

	instanceID, err := c.GetInstID()
	require.NoError(t, err)
	assert.Equal(t, testInstID, instanceID)

	softwareComponents, err := c.GetSoftwareComponents()
	require.NoError(t, err)
	assert.Equal(t, testSoftwareComponents, softwareComponents)

	hashAlgID, err := c.GetHashAlgID()
	require.NoError(t, err)
	assert.Equal(t, testHashAlgID, hashAlgID)

	config, err := c.GetConfig()
	require.NoError(t, err)
	assert.Equal(t, testConfig, config)

	if !includeOptional {
		_, err = c.GetVSI()
		assert.Error(t, err)
		_, err = c.GetManufacturingConfig()
		assert.Error(t, err)
		_, err = c.GetTBBRoTPK()
		assert.Error(t, err)
		_, err = c.GetPeerSigners()
		assert.Error(t, err)
		return
	}

	vsi, err := c.GetVSI()
	require.NoError(t, err)
	assert.Equal(t, testVSI, vsi)

	manufacturingConfig, err := c.GetManufacturingConfig()
	require.NoError(t, err)
	assert.Equal(t, testConfig, manufacturingConfig)

	peerSigners, err := c.GetPeerSigners()
	require.NoError(t, err)
	assert.Equal(t, testPeerSigners, peerSigners)

	tbbRoTPK, err := c.GetTBBRoTPK()
	require.NoError(t, err)
	require.Len(t, tbbRoTPK, 1)

	name, err := tbbRoTPK[0].GetName()
	require.NoError(t, err)
	assert.Equal(t, testTBBRoTPKName, name)

	activeArrayIndex, err := tbbRoTPK[0].GetActiveRoTPKArray()
	require.NoError(t, err)
	assert.Zero(t, activeArrayIndex)

	index, err := tbbRoTPK[0].GetIndex()
	require.NoError(t, err)
	assert.Zero(t, index)

	hash, err := tbbRoTPK[0].GetHash()
	require.NoError(t, err)
	assert.Equal(t, testTBBRoTPKHash, hash)
}
