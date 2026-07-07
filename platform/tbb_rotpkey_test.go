package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TBBRoTPKey_setters_and_getters(t *testing.T) {
	k := TBBRoTPKey{}
	hash := mustHexDecode(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")            // 32 bytes
	badHash := mustHexDecode(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef") // 36 bytes (hash must be 32/48/64 bytes)

	require.NoError(t, k.SetName("ABC"))
	assert.Equal(t, "ABC", *k.Name)
	name, err := k.GetName()
	require.NoError(t, err)
	assert.Equal(t, "ABC", name)

	require.NoError(t, k.SetActiveRoTPKArray(0))
	assert.Equal(t, int32(0), *k.ActiveArray)
	aa, err := k.GetActiveRoTPKArray()
	require.NoError(t, err)
	assert.Equal(t, int32(0), aa)

	require.NoError(t, k.SetActiveRoTPKArray(7))
	assert.Equal(t, int32(7), *k.ActiveArray)
	aa, err = k.GetActiveRoTPKArray()
	require.NoError(t, err)
	assert.Equal(t, int32(7), aa)

	require.NoError(t, k.SetIndex(0))
	assert.Equal(t, int32(0), *k.Index)
	i, err := k.GetIndex()
	require.NoError(t, err)
	assert.Equal(t, int32(0), i)

	require.NoError(t, k.SetIndex(1))
	assert.Equal(t, int32(1), *k.Index)
	i, err = k.GetIndex()
	require.NoError(t, err)
	assert.Equal(t, int32(1), i)

	require.NoError(t, k.SetHash(hash))
	assert.Equal(t, hash, *k.Hash)
	h, err := k.GetHash()
	require.NoError(t, err)
	assert.Equal(t, hash, h)

	err = k.SetHash(badHash)
	assert.EqualError(t, err, "wrong syntax: length 36 (hash MUST be 32, 48 or 64 bytes)")
}
