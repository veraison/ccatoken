package platform

import (
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
		Name:        &testName1,
		ActiveArray: &testActiveRoTPKArray1,
		Index:       &testIndex1,
		Hash:        &testHash1,
	}
	testName2             = "DM"
	testActiveRoTPKArray2 = int32(0)
	testIndex2            = int32(3)
	testHash2             = []byte{0xab, 0xcd, 0xef, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xab, 0xcd, 0xef, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}
	testTBBRoTPKItem2 = TBBRoTPKItem{
		Name:        &testName2,
		ActiveArray: &testActiveRoTPKArray2,
		Index:       &testIndex2,
		Hash:        &testHash2,
	}
)

func Test_TBBRoTPKItems(t *testing.T) {
	keys := TBBRoTPKItems{
		&testTBBRoTPKItem1,
		&testTBBRoTPKItem2,
	}

	require.NoError(t, testTBBRoTPKItem1.Validate())
	require.NoError(t, testTBBRoTPKItem2.Validate())
	assert.NoError(t, keys.Validate())
}
func Test_TBBRoTPKItems_typed_nil_key(t *testing.T) {
	var key *TBBRoTPKItem
	keys := TBBRoTPKItems{key}

	err := keys.Validate()

	assert.EqualError(t, err, "failed at index 0: Nil key in TBBRoTPKItems")
}

func Test_TBBRoTPKItems_nil_key(t *testing.T) {
	keys := TBBRoTPKItems{nil}

	err := keys.Validate()

	assert.EqualError(t, err, "failed at index 0: Nil key in TBBRoTPKItems")
}

func Test_TBBRoTPKItems_empty_key(t *testing.T) {
	keys := TBBRoTPKItems{&TBBRoTPKItem{}}

	err := keys.Validate()

	assert.EqualError(t, err, "failed at index 0: description: missing mandatory field")
}

func Test_TBBRoTPKItems_no_keys(t *testing.T) {
	keys := TBBRoTPKItems{}

	err := keys.Validate()

	assert.EqualError(t, err, "TBBRoTPKItems is included but empty")
}
