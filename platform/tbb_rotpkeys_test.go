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
	testTBBRoTPKey1       = TBBRoTPKey{
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
	testTBBRoTPKey2 = TBBRoTPKey{
		Name:        &testName2,
		ActiveArray: &testActiveRoTPKArray2,
		Index:       &testIndex2,
		Hash:        &testHash2,
	}
)

func Test_TBBRoTPKeys(t *testing.T) {
	keys := TBBRoTPKeys{
		&testTBBRoTPKey1,
		&testTBBRoTPKey2,
	}

	require.NoError(t, testTBBRoTPKey1.Validate())
	require.NoError(t, testTBBRoTPKey2.Validate())
	assert.NoError(t, keys.Validate())
}
func Test_TBBRoTPKeys_typed_nil_key(t *testing.T) {
	var key *TBBRoTPKey
	keys := TBBRoTPKeys{key}

	err := keys.Validate()

	assert.EqualError(t, err, "failed at index 0: Nil key in TBBRoTPKeys")
}

func Test_TBBRoTPKeys_nil_key(t *testing.T) {
	keys := TBBRoTPKeys{nil}

	err := keys.Validate()

	assert.EqualError(t, err, "failed at index 0: Nil key in TBBRoTPKeys")
}

func Test_TBBRoTPKeys_empty_key(t *testing.T) {
	keys := TBBRoTPKeys{&TBBRoTPKey{}}

	err := keys.Validate()

	assert.EqualError(t, err, "failed at index 0: description: missing mandatory field")
}

func Test_TBBRoTPKeys_no_keys(t *testing.T) {
	keys := TBBRoTPKeys{}

	err := keys.Validate()

	assert.EqualError(t, err, "TBBRoTPKeys is included but empty")
}
