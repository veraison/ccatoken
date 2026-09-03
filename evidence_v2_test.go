// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// This file tests the Evidence struct when platform.ClaimsV2 and realm.ClaimsV2 are used.

package ccatoken

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/ccatoken/platform"
	"github.com/veraison/ccatoken/realm"
)

func mustBuildValidRealmClaimsV2(t *testing.T) realm.IClaims {
	c, err := realm.NewClaimsWithProfile(realm.ProfileNameV2)
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

	err = c.SetPubKey(testRAKPubCOSE)
	require.NoError(t, err)

	err = c.SetPubKeyHashAlgID(testPubKeyHashAlgID)
	require.NoError(t, err)

	err = c.SetMECPolicy(testMECPolicy)
	require.NoError(t, err)

	return c
}

func mustBuildValidPlatformClaimsV2(t *testing.T, includeOptional bool) platform.IClaims {
	ic, err := platform.NewClaimsWithProfile(platform.ProfileNameV2)
	require.NoError(t, err)

	c, ok := ic.(*platform.ClaimsV2)
	require.True(t, ok)

	err = c.SetClientID(testClientID)
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

		err = c.SetManufacturingConfig(testConfig)
		require.NoError(t, err)

		tbbRoTPKItem := platform.TBBRoTPKItem{}
		err = tbbRoTPKItem.SetName(testTBBRoTPKName1)
		require.NoError(t, err)

		err = tbbRoTPKItem.SetActiveRoTPKArray(testTBBRoTPKActiveArray1)
		require.NoError(t, err)

		err = tbbRoTPKItem.SetIndex(testTBBRoTPKIndex1)
		require.NoError(t, err)

		err = tbbRoTPKItem.SetHash(testHash1)
		require.NoError(t, err)

		d1 := mustBuildExtensionDeviceAllFields(t)
		d2 := mustBuildExtensionDeviceMinimalFields(t)
		err = c.SetExtension(platform.ExtensionDevices{&d1, &d2})
		require.NoError(t, err)

		err = c.SetTBBRoTPK(platform.TBBRoTPKItems{&tbbRoTPKItem})
		require.NoError(t, err)

		err = c.SetPeerSigners(testPeerSigners)
		require.NoError(t, err)
	}

	return c
}

func mustBuildExtensionDeviceAllFields(t *testing.T) platform.ExtensionDevice {
	d := platform.ExtensionDevice{}
	require.NoError(t, d.SetHashAlgID(testHashAlgID))
	require.NoError(t, d.SetDeviceMeasurementsDigest(testHash1))
	require.NoError(t, d.SetCertificateChainDigest(testHash2))
	require.NoError(t, d.SetUsesIDE(testUsesIDE))
	require.NoError(t, d.SetProtocol(platform.ProtocolSPDM120))
	require.NoError(t, d.SetVCADigest(testHash3))
	require.NoError(t, d.SetDeviceType(platform.DeviceTypeCXLType3))
	require.NoError(t, d.SetEncryptionType(platform.HostSideEncryption))

	require.NoError(t, d.Validate())

	return d
}

func mustBuildExtensionDeviceMinimalFields(t *testing.T) platform.ExtensionDevice {
	d := platform.ExtensionDevice{}
	require.NoError(t, d.SetDeviceMeasurementsDigest(testHash1))
	require.NoError(t, d.SetCertificateChainDigest(testHash2))
	require.NoError(t, d.SetUsesIDE(testUsesIDE))
	require.NoError(t, d.SetProtocol(testOtherProtocol))
	require.NoError(t, d.SetDeviceType(testOtherDeviceType))

	require.NoError(t, d.Validate())

	return d
}

func requireEvidenceV2Claims(t *testing.T, e *Evidence) {
	t.Helper()
	require.NotNil(t, e)

	p, ok := e.PlatformClaims.(*platform.ClaimsV2)
	require.True(t, ok, "platform claims have type %T, want *platform.ClaimsV2", e.PlatformClaims)

	profile, err := p.GetProfile()
	require.NoError(t, err)
	assert.Equal(t, platform.ProfileNameV2, profile)

	clientID, err := p.GetClientID()
	require.NoError(t, err)
	assert.Equal(t, int32(1), clientID)

	r, ok := e.RealmClaims.(*realm.ClaimsV2)
	require.True(t, ok, "realm claims have type %T, want *realm.ClaimsV2", e.RealmClaims)

	profile, err = r.GetProfile()
	require.NoError(t, err)
	assert.Equal(t, realm.ProfileNameV2, profile)

	mecPolicy, err := r.GetMECPolicy()
	require.NoError(t, err)
	assert.Equal(t, realm.MECPolicyPrivate, mecPolicy)
}

func TestEvidenceV2_DecodeDraftRev03_ok(t *testing.T) {
	// This token's hex encoding was directly copied from
	// draft-ffm-rats-cca-token-03, section A.1.5
	rev03Token := mustHexDecode(t, testGoodCCATokenRev03)
	evidence, err := DecodeAndValidateEvidenceFromCBOR(rev03Token)
	require.NoError(t, err)
	requireEvidenceV2Claims(t, evidence)

	// This token's hex encoding was generated from the diag notation
	// found in draft-ffm-rats-cca-token-03, section A.1.5,
	// using testvectors/cbor/build-test-vectors.sh
	rev03DiagToken := mustHexDecode(t, testGeneratedCcaTokenRev03)
	generatedEvidence, err := DecodeAndValidateEvidenceFromCBOR(rev03DiagToken)
	require.NoError(t, err)
	requireEvidenceV2Claims(t, generatedEvidence)

	assert.Equal(t, evidence.PlatformClaims, generatedEvidence.PlatformClaims)
	assert.Equal(t, evidence.RealmClaims, generatedEvidence.RealmClaims)

	err = evidence.Validate()
	require.NoError(t, err)

	err = generatedEvidence.Validate()
	require.NoError(t, err)
}

func TestEvidenceV2_JSONRoundTrip_ok(t *testing.T) {
	evidenceIn := &Evidence{}
	err := evidenceIn.SetClaims(
		mustBuildValidPlatformClaimsV2(t, false),
		mustBuildValidRealmClaimsV2(t),
	)
	require.NoError(t, err)

	encoded, err := ValidateAndEncodeEvidenceToJSON(evidenceIn)
	require.NoError(t, err)

	evidenceOut, err := DecodeAndValidateEvidenceFromJSON(encoded)
	require.NoError(t, err)
	requireEvidenceV2Claims(t, evidenceOut)

	reencoded, err := ValidateAndEncodeEvidenceToJSON(evidenceOut)
	require.NoError(t, err)
	assert.JSONEq(t, string(encoded), string(reencoded))
}

func TestEvidenceV2_JSONRoundTrip_with_optional_platform_claims_ok(t *testing.T) {
	evidenceIn := &Evidence{}
	err := evidenceIn.SetClaims(
		mustBuildValidPlatformClaimsV2(t, true),
		mustBuildValidRealmClaimsV2(t),
	)
	require.NoError(t, err)

	encoded, err := ValidateAndEncodeEvidenceToJSON(evidenceIn)
	require.NoError(t, err)

	evidenceOut, err := DecodeAndValidateEvidenceFromJSON(encoded)
	require.NoError(t, err)
	requireEvidenceV2Claims(t, evidenceOut)

	reencoded, err := ValidateAndEncodeEvidenceToJSON(evidenceOut)
	require.NoError(t, err)
	assert.JSONEq(t, string(encoded), string(reencoded))
}

func TestEvidenceV2_SetClaimsInvalidPlatformClientID_nok(t *testing.T) {
	evidence := &Evidence{}
	platformClaims := mustBuildValidPlatformClaimsV2(t, false)
	var k int32 = 0
	platformClaims.(*platform.ClaimsV2).ClientID = &k

	err := evidence.SetClaims(
		platformClaims,
		mustBuildValidRealmClaimsV2(t),
	)
	assert.EqualError(t, err, "validation of cca-platform-claims failed: validating client id: wrong syntax: client id MUST be 1")
}

func TestEvidenceV2_SetClaimsMissingPlatformClientID_nok(t *testing.T) {
	evidence := &Evidence{}
	platformClaims := mustBuildValidPlatformClaimsV2(t, false)
	platformClaims.(*platform.ClaimsV2).ClientID = nil

	err := evidence.SetClaims(
		platformClaims,
		mustBuildValidRealmClaimsV2(t),
	)
	assert.EqualError(t, err, "validation of cca-platform-claims failed: validating client id: missing mandatory claim")
}

func TestEvidenceV2_SetClaimsMissingRealmMECPolicy_nok(t *testing.T) {
	evidence := &Evidence{}
	realmClaims := mustBuildValidRealmClaimsV2(t)
	realmClaims.(*realm.ClaimsV2).MECPolicy = nil

	err := evidence.SetClaims(
		mustBuildValidPlatformClaimsV2(t, false),
		realmClaims,
	)
	assert.EqualError(t, err, "validation of cca-realm-claims failed: validating realm MEC policy claim: missing mandatory claim")
}

func TestEvidenceV2_SetClaimsInvalidRealmMECPolicy_nok(t *testing.T) {
	evidence := &Evidence{}
	realmClaims := mustBuildValidRealmClaimsV2(t)
	realmClaims.(*realm.ClaimsV2).MECPolicy = &testInvalidMECPolicy

	err := evidence.SetClaims(
		mustBuildValidPlatformClaimsV2(t, false),
		realmClaims,
	)
	assert.EqualError(t, err, "validation of cca-realm-claims failed: validating realm MEC policy claim: wrong syntax: MEC policy MUST be 'private' or 'shared'")
}

func TestEvidenceV2_SignDecodeVerify_ok(t *testing.T) {
	evidenceIn := &Evidence{}
	err := evidenceIn.SetClaims(
		mustBuildValidPlatformClaimsV2(t, true),
		mustBuildValidRealmClaimsV2(t),
	)
	require.NoError(t, err)

	encoded, err := evidenceIn.ValidateAndSign(
		signerFromJWK(t, testCPAK),
		signerFromJWK(t, testRAK),
	)
	require.NoError(t, err)

	evidenceOut, err := DecodeAndValidateEvidenceFromCBOR(encoded)
	require.NoError(t, err)
	requireEvidenceV2Claims(t, evidenceOut)

	err = evidenceOut.Verify(pubKeyFromJWK(t, testCPAK))
	assert.NoError(t, err)
}
