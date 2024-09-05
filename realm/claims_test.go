package realm

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/psatoken"
)

func mustBuildValidCcaRealmClaims(t *testing.T) IClaims {
	c := NewClaims()

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

	err = c.SetPubKey(TestAltRAKPubCOSE)
	require.NoError(t, err)

	err = c.SetPubKeyHashAlgID(testPubKeyHashAlgID)
	require.NoError(t, err)

	return c
}

func Test_NewCcaRealmClaims_ok(t *testing.T) {
	c := mustBuildValidCcaRealmClaims(t)

	err := c.Validate()
	assert.NoError(t, err)
}

func Test_CcaRealmClaims_Set_nok(t *testing.T) {
	c := NewClaims()

	err := c.SetChallenge([]byte("123"))
	expectedErr := "wrong syntax: length 3 (hash MUST be 64 bytes)"
	assert.EqualError(t, err, expectedErr)

	err = c.SetPersonalizationValue([]byte("personalizationVal"))
	expectedErr = "wrong syntax: length 18 (personalization value MUST be 64 bytes)"
	assert.EqualError(t, err, expectedErr)

	err = c.SetInitialMeasurement([]byte("random"))
	expectedErr = "wrong syntax: length 6 (realm measurement MUST be 32, 48 or 64 bytes)"
	assert.EqualError(t, err, expectedErr)

	err = c.SetExtensibleMeasurements([][]byte{})
	expectedErr = "missing mandatory claim realm extended measurements"
	assert.EqualError(t, err, expectedErr)

	err = c.SetHashAlgID("")
	expectedErr = "wrong syntax: empty string"
	assert.EqualError(t, err, expectedErr)

	err = c.SetPubKey([]byte("not-a-valid-point"))
	expectedErr = "wrong syntax"
	assert.ErrorContains(t, err, expectedErr)

	err = c.SetPubKey([]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff,
	})
	expectedErr = "wrong syntax"
	assert.ErrorContains(t, err, expectedErr)

	err = c.SetPubKeyHashAlgID("")
	expectedErr = "invalid null string set for realm pubkey hash alg ID"
	assert.EqualError(t, err, expectedErr)
}

func Test_CcaRealmClaims_MarshalCBOR_invalid(t *testing.T) {
	c := NewClaims()
	expectedErr := `validating realm challenge claim: missing mandatory claim`

	_, err := ValidateAndEncodeClaimsToCBOR(c)

	assert.EqualError(t, err, expectedErr)
}

func Test_CcaRealmClaims_MarshalCBOR_all_claims(t *testing.T) {
	c := mustBuildValidCcaRealmClaims(t)
	expected := mustHexDecode(t, testEncodedCcaRealmClaimsAll)

	actual, err := ValidateAndEncodeClaimsToCBOR(c)

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_CcaRealmLegacyClaims_UnmarshalCBOR_ok(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaRealmLegacyClaimsAll)

	c, err := DecodeAndValidateClaimsFromCBOR(buf)
	assert.NoError(t, err)

	k, err := c.GetPubKey()
	assert.NoError(t, err)
	assert.Equal(t, TestRAKPubRaw, k)
}

func Test_CcaRealmClaims_UnmarshalCBOR_ok(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaRealmClaimsAll)

	c, err := DecodeAndValidateClaimsFromCBOR(buf)

	assert.NoError(t, err)

	// mandatory
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

func Test_CcaRealmClaims_UnmarshalCBOR_bad_input(t *testing.T) {
	buf := mustHexDecode(t, testNotCBOR)
	expectedErr := "unexpected EOF"

	_, err := DecodeAndValidateClaimsFromCBOR(buf)

	assert.EqualError(t, err, expectedErr)
}

func Test_CcaRealmClaims_UnmarshalCBOR_missing_mandatory_claims(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaRealmClaimsMissingMandNonce)
	expectedErr := "validating realm challenge claim: missing mandatory claim"

	_, err := DecodeAndValidateClaimsFromCBOR(buf)
	assert.EqualError(t, err, expectedErr)

	buf = mustHexDecode(t, testEncodedCcaClaimsMissingMandInitialMeas)
	expectedErr = "validating realm initial measurements claim: missing mandatory claim"

	_, err = DecodeAndValidateClaimsFromCBOR(buf)
	assert.EqualError(t, err, expectedErr)

	buf = mustHexDecode(t, testEncodedCcaClaimsMissingMandHashAlgID)
	expectedErr = "validating realm hash alg ID claim: missing mandatory claim"

	_, err = DecodeAndValidateClaimsFromCBOR(buf)
	assert.EqualError(t, err, expectedErr)

	buf = mustHexDecode(t, testEncodedCcaClaimsMissingMandPubKey)
	expectedErr = "validating realm public key claim: missing mandatory claim"

	_, err = DecodeAndValidateClaimsFromCBOR(buf)
	assert.EqualError(t, err, expectedErr)

	buf = mustHexDecode(t, testEncodedCcaClaimsMissingMandExtendedMeas)
	expectedErr = "validating realm extended measurements claim: missing mandatory claim"

	_, err = DecodeAndValidateClaimsFromCBOR(buf)
	assert.EqualError(t, err, expectedErr)
}

func Test_CcaRealm_Claims_MarshalJSON_ok(t *testing.T) {
	c := mustBuildValidCcaRealmClaims(t)

	expected := `{
  "cca-realm-profile": "tag:arm.com,2023:realm#1.0.0",
  "cca-realm-challenge": "QUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQg==",
  "cca-realm-personalization-value": "QURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBRA==",
  "cca-realm-initial-measurement": "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw==",
  "cca-realm-extensible-measurements": [
    "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw==",
    "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw==",
    "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw==",
    "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw=="
  ]
  ,
  "cca-realm-hash-algo-id": "sha-256",
  "cca-realm-public-key": "pAECIAIhWDB2+YgJG+WF7UGAGuz6uFhUjGMFfhaw5nYSC70NL5wp4FbF1BoBMOucIVF4mdwjFGsiWDAo4bBivT6ksxX9IZ8cu1KMtudMpJvhZ3NzT2GhymEDGyu/PZGPL5T/xCKOUJGVRK4=",
  "cca-realm-public-key-hash-algo-id": "sha-512"
}`
	actual, err := ValidateAndEncodeClaimsToJSON(c)
	assert.NoError(t, err)
	assert.JSONEq(t, expected, string(actual))
}

func Test_CcaRealmClaims_UnmarshalJSON_ok(t *testing.T) {
	tv := `{
  "cca-realm-challenge": "QUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQg==",
  "cca-realm-personalization-value": "QURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBRA==",
  "cca-realm-initial-measurement": "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw==",
  "cca-realm-extensible-measurements": [
    "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw==",
    "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw==",
    "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw==",
    "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw=="
  ]
  ,
  "cca-realm-hash-algo-id": "sha-256",
  "cca-realm-public-key": "pAECIAIhWDB2+YgJG+WF7UGAGuz6uFhUjGMFfhaw5nYSC70NL5wp4FbF1BoBMOucIVF4mdwjFGsiWDAo4bBivT6ksxX9IZ8cu1KMtudMpJvhZ3NzT2GhymEDGyu/PZGPL5T/xCKOUJGVRK4=",
  "cca-realm-public-key-hash-algo-id": "sha-512"
}`
	_, err := DecodeAndValidateClaimsFromJSON([]byte(tv))

	assert.NoError(t, err)
}

func Test_CcaRealmClaims_UnmarshalJSON_invalid_json(t *testing.T) {
	tv := testNotJSON
	expectedErr := `unexpected end of JSON input`

	_, err := DecodeAndValidateClaimsFromJSON(tv)

	assert.EqualError(t, err, expectedErr)
}

func Test_CcaRealmClaims_UnmarshalJSON_negatives(t *testing.T) {
	tvs := []string{
		/* 0 */ "testvectors/json/test-invalid-nonce.json",
		/* 1 */ "testvectors/json/test-invalid-extended-meas.json",
		/* 2 */ "testvectors/json/test-invalid-initial-meas.json",
		/* 3 */ "testvectors/json/test-invalid-public-key.json",
		/* 4 */ "testvectors/json/test-invalid-personalization-val.json",
		/* 5 */ "testvectors/json/test-missing-nonce.json",
		/* 6 */ "testvectors/json/test-missing-hash-alg-id.json",
		/* 7 */ "testvectors/json/test-missing-personalization-val.json",
		/* 8 */ "testvectors/json/test-missing-initial-meas.json",
		/* 9 */ "testvectors/json/test-missing-extended-meas.json",
		/* 10 */ "testvectors/json/test-missing-public-key.json",
		/* 11 */ "testvectors/json/test-missing-public-key-alg-id.json",
	}
	for i, fn := range tvs {
		buf, err := os.ReadFile(fn)
		require.NoError(t, err)

		_, err = DecodeAndValidateClaimsFromJSON(buf)

		assert.Error(t, err, "test vector %d failed", i)
	}
}

func Test_SetPubKey_legacy_ok(t *testing.T) {
	c := newClaimsForDecoding()
	err := c.SetPubKey(TestRAKPubRaw)
	assert.NoError(t, err)
}

func Test_SetPubKey_legacy_bad(t *testing.T) {
	c := newClaimsForDecoding()
	err := c.SetPubKey(TestAltRAKPubCOSE)
	assert.ErrorContains(t, err, "wrong syntax")
}

func Test_GetProfile_legacy(t *testing.T) {
	c := newClaimsForDecoding()
	_, err := c.GetProfile()
	assert.ErrorIs(t, err, psatoken.ErrOptionalClaimMissing)
}

func Test_GetProfile_ok(t *testing.T) {
	c := NewClaims()
	profile, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, ProfileName, profile)
}
