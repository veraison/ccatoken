// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testClientID = int32(1)
)

func mustBuildValidClaimsV2(t *testing.T) *ClaimsV2 {
	c := NewClaimsV2().(*ClaimsV2)

	err := c.SetClientID(testClientID)
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

	return c
}

func Test_NewClaimsV2_ok(t *testing.T) {
	c := NewClaimsV2()

	actual, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, ProfileNameV2, actual)
}

func Test_ClaimsV2_Validate_mandatory_only_claims(t *testing.T) {
	c := mustBuildValidClaimsV2(t)

	err := c.Validate()
	assert.NoError(t, err)
}

func Test_ClaimsV2_Validate_all_new_claims(t *testing.T) {
	c := mustBuildValidClaimsV2(t)
	tbbRoTPKItem := TBBRoTPKItem{}

	require.NoError(t, c.SetManufacturingConfig(testConfig))
	require.NoError(t, tbbRoTPKItem.SetName("DM"))
	require.NoError(t, tbbRoTPKItem.SetActiveRoTPKArray(0))
	require.NoError(t, tbbRoTPKItem.SetIndex(0))
	require.NoError(t, tbbRoTPKItem.SetHash(testMeasurementValue))
	require.NoError(t, c.SetTBBRoTPK([]ITBBRoTPKItem{&tbbRoTPKItem}))
	require.NoError(t, c.SetPeerSigners(testSignerID))

	err := c.Validate()
	assert.NoError(t, err)
}

func Test_ClaimsV2_Validate_new_claim_failures(t *testing.T) {
	c := mustBuildValidClaimsV2(t)
	c.ClientID = nil
	assert.EqualError(t, c.Validate(), "validating client id: missing mandatory claim")

	c = mustBuildValidClaimsV2(t)
	emptyManufacturingConfig := []byte{}
	assert.EqualError(t, c.SetManufacturingConfig(emptyManufacturingConfig), "wrong syntax: manufacturing config")

	c = mustBuildValidClaimsV2(t)
	c.TBBRoTPK = &TBBRoTPKItems{values: []*TBBRoTPKItem{{}}}
	assert.EqualError(t, c.Validate(), "validating platform TBB ROTPK: failed at index 0: description: missing mandatory field")

	c = mustBuildValidClaimsV2(t)
	badPeerSigners := []byte{}
	c.PeerSigners = &badPeerSigners
	assert.EqualError(t, c.Validate(), "validating platform peer signers: wrong syntax: peer signers")
}
