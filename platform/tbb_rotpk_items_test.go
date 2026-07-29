// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testName1             = "CM"
	testActiveRoTPKArray1 = int32(1)
	testIndex1            = int32(0)
	testHash1             = []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}
	testTBBRoTPKItem1     = TBBRoTPKItem{
		Name:             &testName1,
		ActiveArrayIndex: &testActiveRoTPKArray1,
		Index:            &testIndex1,
		Hash:             &testHash1,
	}
	testName2             = "DM"
	testActiveRoTPKArray2 = int32(0)
	testIndex2            = int32(3)
	testHash2             = []byte{0xab, 0xcd, 0xef, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xab, 0xcd, 0xef, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}
	testTBBRoTPKItem2 = TBBRoTPKItem{
		Name:             &testName2,
		ActiveArrayIndex: &testActiveRoTPKArray2,
		Index:            &testIndex2,
		Hash:             &testHash2,
	}
)

func Test_TBBRoTPKItems_Copy(t *testing.T) {
	keys := TBBRoTPKItems{}
	keys = append(keys, &testTBBRoTPKItem1, &testTBBRoTPKItem2)

	c := ClaimsV2{}
	c.SetTBBRoTPK([]*TBBRoTPKItem{&testTBBRoTPKItem1, &testTBBRoTPKItem2})

	vals, err := keys.Copy()
	require.NoError(t, err)
	assert.Equal(t, TBBRoTPKItems{&testTBBRoTPKItem1, &testTBBRoTPKItem2}, vals)

	vals[0] = nil
	assert.Equal(t, TBBRoTPKItems{nil, &testTBBRoTPKItem2}, vals)
	assert.Equal(t, TBBRoTPKItems{&testTBBRoTPKItem1, &testTBBRoTPKItem2}, keys)
}

func Test_TBBRoTPKItems_Validate(t *testing.T) {
	require.NoError(t, testTBBRoTPKItem1.Validate())
	require.NoError(t, testTBBRoTPKItem2.Validate())

	keys := TBBRoTPKItems{&testTBBRoTPKItem1, &testTBBRoTPKItem2}
	assert.NoError(t, keys.Validate())

	keys[1] = nil
	assert.EqualError(t, keys.Validate(), "failed at index 1: nil key in TBBRoTPKItems")
}

func Test_TBBRoTPKItems_codec_roundtrip(t *testing.T) {
	keys := TBBRoTPKItems{&testTBBRoTPKItem1, &testTBBRoTPKItem2}

	jsonBytes, err := json.Marshal(keys)
	require.NoError(t, err)

	var fromJSON TBBRoTPKItems
	require.NoError(t, json.Unmarshal(jsonBytes, &fromJSON))
	require.NoError(t, fromJSON.Validate())
	assert.Equal(t, TBBRoTPKItems{&testTBBRoTPKItem1, &testTBBRoTPKItem2}, fromJSON)

	cborBytes, err := em.Marshal(keys)
	require.NoError(t, err)

	var fromCBOR TBBRoTPKItems
	require.NoError(t, dm.Unmarshal(cborBytes, &fromCBOR))
	require.NoError(t, fromCBOR.Validate())
	assert.Equal(t, TBBRoTPKItems{&testTBBRoTPKItem1, &testTBBRoTPKItem2}, fromCBOR)
}

func Test_TBBRoTPKItems_nil_key(t *testing.T) {
	keys := TBBRoTPKItems{nil}

	err := keys.Validate()

	assert.EqualError(t, err, "failed at index 0: nil key in TBBRoTPKItems")
}

func Test_TBBRoTPKItems_empty_key(t *testing.T) {
	keys := TBBRoTPKItems{{}}

	err := keys.Validate()

	assert.EqualError(t, err, "failed at index 0: name: missing mandatory field")
}
