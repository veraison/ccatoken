// Copyright 2021-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package realm

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/eat"
)

func Test_NewClaimsWithProfile_profile_unknown(t *testing.T) {
	expectedErr := `unsupported profile "http://unknown.example"`

	_, err := NewClaimsWithProfile("http://unknown.example")
	assert.EqualError(t, err, expectedErr)
}

func Test_NewClaimsWithProfile_ok(t *testing.T) {
	testProfiles := []string{
		"",
		ProfileName,
		ProfileNameV2,
	}
	expectedProfileNames := []string{
		// Cannot create claim set without a profile name. "tag:arm.com,2023:realm#1.0.0" will be set if an empty string is provided.
		ProfileName,
		ProfileName,
		ProfileNameV2,
	}
	expectedTypes := []IClaims{
		&Claims{},
		&Claims{},
		&ClaimsV2{},
	}

	for i, profile := range testProfiles {
		cl, err := NewClaimsWithProfile(profile)
		assert.NoError(t, err)
		assert.IsType(t, expectedTypes[i], cl)
		name, err := cl.GetProfile()
		assert.NoError(t, err)
		assert.Equal(t, expectedProfileNames[i], name)
	}
}

const testProfileName = "tag:arm.com,1901:realm#2.3.4"

type testClaims struct {
	ClaimsV2
	Profile *eat.Profile `cbor:"265,keyasint" json:"my-registered-profile-tag,omitempty"`
}

type testProfile struct{}

func (testProfile) GetName() string {
	return testProfileName
}

func (testProfile) GetClaims() IClaims {
	return &testClaims{}
}

func (testProfile) GetUninitializedClaims() IClaims {
	return &testClaims{}
}

func Test_DecodeClaimsFromCBOR_registered_profile_ok(t *testing.T) {
	require.NoError(t, RegisterProfile(testProfile{}))

	buf := mustHexDecode(t, testEncodedCcaRealmClaimsRegisteredProfile)
	c, err := DecodeClaimsFromCBOR(buf)
	require.NoError(t, err)
	assert.IsType(t, &testClaims{}, c)

	t.Cleanup(func() {
		delete(profilesRegister, testProfileName)
		assert.NotContains(t, profilesRegister, testProfileName)
	})
}

func Test_DecodeClaimsFromCBOR_unregistered_profile_nok(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaRealmClaimsUnregisteredProfile)
	_, err := DecodeClaimsFromCBOR(buf)
	require.Contains(t, err.Error(), "unknown profile")
}

func Test_DecodeClaimsFromJSON_registered_profile_ok(t *testing.T) {
	require.NoError(t, RegisterProfile(testProfile{}))

	buf, err := os.ReadFile("testvectors/json/profile-registry/test-valid-registered-jsontag.json")
	require.NoError(t, err)

	c, err := DecodeClaimsFromJSON(buf)
	require.NoError(t, err)
	assert.IsType(t, &testClaims{}, c)

	t.Cleanup(func() {
		delete(profilesRegister, testProfileName)
		assert.NotContains(t, profilesRegister, testProfileName)
	})
}

func Test_DecodeClaimsFromJSON_unregistered_profile_nok(t *testing.T) {
	buf, err := os.ReadFile("testvectors/json/profile-registry/test-unregistered-profile.json")
	require.NoError(t, err)

	_, err = DecodeClaimsFromJSON(buf)
	assert.Contains(t, err.Error(), "unknown profile")
}

func Test_DecodeClaimsFromJSON_unregistered_jsontag_returns_default_profile(t *testing.T) {
	buf, err := os.ReadFile("testvectors/json/profile-registry/test-unregistered-jsontag.json")
	require.NoError(t, err)

	c, err := DecodeClaimsFromJSON(buf)
	require.NoError(t, err)
	// Defaults to ClaimsV1 when no profile is found, as it has not been registered
	assert.IsType(t, &Claims{}, c)
}

func Test_DecodeClaimsFromJSON_non_string_profile_nok(t *testing.T) {
	_, err := DecodeClaimsFromJSON([]byte(`{"cca-realm-profile":null}`))
	assert.EqualError(t, err, `profile "cca-realm-profile" must be a string`)
}
