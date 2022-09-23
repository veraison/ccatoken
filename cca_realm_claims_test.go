package ccatoken

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustBuildValidCcaRealmClaims(t *testing.T) IClaims {
	c, err := NewClaims()
	require.NoError(t, err)

	err = c.SetChallenge(testChallenge)
	require.NoError(t, err)

	err = c.SetPersonalizationValue(testPersonalizationVal)
	require.NoError(t, err)

	err = c.SetInitialMeasurements(testInitMeas)
	require.NoError(t, err)

	err = c.SetExtensibleMeasurements(testExtensibleMeas)
	require.NoError(t, err)

	err = c.SetHashAlgID(testHashAlgID)
	require.NoError(t, err)

	err = c.SetPubKey(testPubKey)
	require.NoError(t, err)

	err = c.SetPubKeyHashAlgID(testPubKeyHashAlgID)
	require.NoError(t, err)

	return c
}

func Test_NewCca_Realm_Claims_ok(t *testing.T) {
	c := mustBuildValidCcaRealmClaims(t)

	err := c.Validate()
	assert.NoError(t, err)
}

func Test_Cca_Realm_Claims_Set_nok(t *testing.T) {
	c, err := NewClaims()
	require.NoError(t, err)

	err = c.SetChallenge([]byte("123"))
	expectedErr := "wrong syntax for claim: length 3 (cca-hash-type MUST be 64 bytes)"
	assert.EqualError(t, err, expectedErr)

	err = c.SetPersonalizationValue([]byte("personalizationVal"))
	expectedErr = "wrong syntax for claim: length 18 (cca-personalization-value MUST be 64 bytes)"
	assert.EqualError(t, err, expectedErr)

	err = c.SetInitialMeasurements([]byte("random"))
	expectedErr = "wrong syntax for claim: length 6 (cca-realm-measurement MUST be 32, 48 or 64 bytes)"
	assert.EqualError(t, err, expectedErr)

	err = c.SetExtensibleMeasurements([][]byte{})
	expectedErr = "missing mandatory claim cca-realm-extended-measurements:"
	assert.EqualError(t, err, expectedErr)

	err = c.SetHashAlgID("blank")
	expectedErr = "wrong syntax for claim: wrong syntax"
	assert.EqualError(t, err, expectedErr)

	err = c.SetPubKey([]byte("random-key"))
	expectedErr = "wrong syntax for claim: length 10 (cca-realm-public-key MUST be 97 bytes)"
	assert.EqualError(t, err, expectedErr)

	err = c.SetPubKeyHashAlgID("")
	expectedErr = "invalid null string set for cca-realm-pubkey-hash-alg-id"
	assert.EqualError(t, err, expectedErr)
}

func Test_Cca_Realm_Claims_ToCBOR_invalid(t *testing.T) {
	c, err := NewClaims()
	require.NoError(t, err)

	expectedErr := `validation of CCA realm claims failed: validating cca-realm-challege claim : missing mandatory claim`

	_, err = c.ToCBOR()

	assert.EqualError(t, err, expectedErr)
}

func Test_Cca_Realm_Claims_ToCBOR_all_claims(t *testing.T) {
	c := mustBuildValidCcaRealmClaims(t)

	expected := mustHexDecode(t, testEncodedCcaRealmClaimsAll)

	actual, err := c.ToCBOR()

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_Cca_Realm_Claims_FromCBOR_ok(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaRealmClaimsAll)

	var c CcaRealmClaims
	err := c.FromCBOR(buf)
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
	actualInitMeas, err := c.GetInitialMeasurements()
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

	expectedPubKey := testPubKey
	actualPubKey, err := c.GetPubKey()
	assert.NoError(t, err)
	assert.Equal(t, expectedPubKey, actualPubKey)

}

func Test_Cca_Realm_Claims_FromCBOR_bad_input(t *testing.T) {
	buf := mustHexDecode(t, testNotCBOR)

	expectedErr := "CBOR decoding of CCA realm claims failed: unexpected EOF"

	var c CcaRealmClaims
	err := c.FromCBOR(buf)

	assert.EqualError(t, err, expectedErr)
}

func Test_Cca_Realm_Claims_FromCBOR_missing_mandatory_claims(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaRealmClaimsMissingMandNonce)

	expectedErr := "validation of CCA realm claims failed: validating cca-realm-challege claim : missing mandatory claim"

	var c CcaRealmClaims
	err := c.FromCBOR(buf)
	assert.EqualError(t, err, expectedErr)

	buf = mustHexDecode(t, testEncodedCcaClaimsMissingMandInitialMeas)

	expectedErr = "validation of CCA realm claims failed: validating cca-realm-initial-measurements claim : missing mandatory claim"
	c = CcaRealmClaims{}
	err = c.FromCBOR(buf)
	assert.EqualError(t, err, expectedErr)

	buf = mustHexDecode(t, testEncodedCcaClaimsMissingMandHashAlgID)

	expectedErr = "validation of CCA realm claims failed: validating cca-realm-hash-alg-id claim : missing mandatory claim"
	c = CcaRealmClaims{}
	err = c.FromCBOR(buf)
	assert.EqualError(t, err, expectedErr)

	buf = mustHexDecode(t, testEncodedCcaClaimsMissingMandPubKey)

	expectedErr = "validation of CCA realm claims failed: validating cca-realm-public-key claim : missing mandatory claim"
	c = CcaRealmClaims{}
	err = c.FromCBOR(buf)
	assert.EqualError(t, err, expectedErr)

	buf = mustHexDecode(t, testEncodedCcaClaimsMissingMandExtendedMeas)

	expectedErr = "validation of CCA realm claims failed: validating cca-realm-extended-measurements claim : missing mandatory claim"
	c = CcaRealmClaims{}
	err = c.FromCBOR(buf)
	assert.EqualError(t, err, expectedErr)

}

func Test_CcaRealm_Claims_ToJSON_ok(t *testing.T) {
	c := mustBuildValidCcaRealmClaims(t)

	expected := `{
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
  "cca-realm-public-key": "WUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWQ==",
  "cca-realm-public-key-hash-algo-id": "sha-512"
}`
	actual, err := c.ToJSON()
	assert.NoError(t, err)
	assert.JSONEq(t, expected, string(actual))
}

func Test_Cca_Realm_Claims_FromJSON_ok(t *testing.T) {
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
  "cca-realm-public-key": "WUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWQ==",
  "cca-realm-public-key-hash-algo-id": "sha-512"
}`

	var c CcaRealmClaims

	err := c.FromJSON([]byte(tv))
	assert.NoError(t, err)
}

func Test_Cca_Realm_Claims_FromJSON_invalid_json(t *testing.T) {
	tv := testNotJSON

	expectedErr := `JSON decoding of CCA realm claims failed: unexpected end of JSON input`

	var c CcaRealmClaims

	err := c.FromJSON(tv)
	assert.EqualError(t, err, expectedErr)
}

func Test_Cca_Realm_Cliams_FromJSON_negatives(t *testing.T) {
	tvs := []string{
		/* 0 */ "testvectors/json/test-invalid-nonce.json",
		/* 1 */ "testvectors/json/test-invalid-extended-meas.json",
		/* 2 */ "testvectors/json/test-invalid-initial-meas.json",
		/* 3 */ "testvectors/json/test-invalid-hash-alg-id.json",
		/* 4 */ "testvectors/json/test-invalid-personalization-val.json",
		/* 5 */ "testvectors/json/test-missing-nonce.json",
		/* 6 */ "testvectors/json/test-missing-hash-alg-id.json",
		/* 7 */ "testvectors/json/test-missing-personalization-val.json",
		/* 8 */ "testvectors/json/test-missing-initial-meas.json",
		/* 9 */ "testvectors/json/test-missing-extended-meas.json",
		/* 10 */ "testvectors/json/test-missing-public-key.json",
		/* 11 */ "testvectors/json/test-missing-public-key-alg-id.json",
		/* 12 */ "testvectors/json/test-invalid-public-key.json",
	}
	for i, fn := range tvs {
		buf, err := os.ReadFile(fn)
		require.NoError(t, err)

		var claimsSet CcaRealmClaims

		err = claimsSet.FromJSON(buf)
		assert.Error(t, err, "test vector %d failed", i)
	}
}
