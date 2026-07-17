package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TBBRoTPKItem_name_setter_and_getter(t *testing.T) {
	k := TBBRoTPKItem{}

	require.NoError(t, k.SetName("DM"))
	assert.Equal(t, "DM", *k.Name)
	name, err := k.GetName()
	require.NoError(t, err)
	assert.Equal(t, "DM", name)

	require.NoError(t, k.SetName("cM"))
	assert.Equal(t, "cM", *k.Name)
	name, err = k.GetName()
	require.NoError(t, err)
	assert.Equal(t, "cM", name)

	err = k.SetName("ABC")
	assert.EqualError(t, err, "invalid name: ABC, must be 'CM' or 'DM'")
}

func Test_TBBRoTPKItem_active_array_index_setter_and_getter(t *testing.T) {
	k := TBBRoTPKItem{}

	require.NoError(t, k.SetActiveRoTPKArray(0))
	assert.Equal(t, int32(0), *k.ActiveArrayIndex)
	aa, err := k.GetActiveRoTPKArray()
	require.NoError(t, err)
	assert.Equal(t, int32(0), aa)

	require.NoError(t, k.SetActiveRoTPKArray(7))
	assert.Equal(t, int32(7), *k.ActiveArrayIndex)
	aa, err = k.GetActiveRoTPKArray()
	require.NoError(t, err)
	assert.Equal(t, int32(7), aa)
}

func Test_TBBRoTPKItem_index_setter_and_getter(t *testing.T) {
	k := TBBRoTPKItem{}

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
}

func Test_TBBRoTPKItem_hash_setter_and_getter(t *testing.T) {
	k := TBBRoTPKItem{}
	require.NoError(t, k.SetHash(testHash1))
	assert.Equal(t, testHash1, *k.Hash)
	h, err := k.GetHash()
	require.NoError(t, err)
	assert.Equal(t, testHash1, h)

	err = k.SetHash(testBadHash)
	assert.EqualError(t, err, "wrong syntax: length 36 (hash MUST be 32, 48 or 64 bytes)")
}
