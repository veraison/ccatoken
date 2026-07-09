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
