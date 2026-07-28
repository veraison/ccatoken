package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ExtensionDevices_Add(t *testing.T) {
	ds := ExtensionDevices{}

	d1 := mustBuildExtensionDevice6Fields(t)
	d2 := mustBuildExtensionDevice8Fields(t)
	d3 := mustBuildExtensionDevice8Fields(t)

	err := ds.Add(&d1, &d2)
	require.NoError(t, err)
	assert.Len(t, ds, 2)
	assert.Equal(t, *ds[0], d1)
	assert.Equal(t, *ds[1], d2)

	err = ds.Add(&d3)
	require.NoError(t, err)
	assert.Len(t, ds, 3)
	assert.Equal(t, *ds[2], d3)
}

func Test_ExtensionDevices_Validate(t *testing.T) {
	ds := ExtensionDevices{}

	d1 := mustBuildExtensionDevice6Fields(t)
	d2 := mustBuildExtensionDevice8Fields(t)
	d3 := mustBuildExtensionDevice8Fields(t)

	err := ds.Add(&d1, &d2, &d3)
	require.NoError(t, err)

	err = ds.Validate()
	assert.NoError(t, err)
}

func Test_ExtensionDevices_Replace(t *testing.T) {
	ds := ExtensionDevices{}

	d1 := mustBuildExtensionDevice6Fields(t)
	d2 := mustBuildExtensionDevice8Fields(t)

	require.NoError(t, ds.Replace([]*ExtensionDevice{&d1}))
	assert.Len(t, ds, 1)
	require.Equal(t, ds[0], &d1)

	require.NoError(t, ds.Replace([]*ExtensionDevice{&d2}))
	assert.Len(t, ds, 1)
	require.Equal(t, ds[0], &d2)
}

func Test_ExtensionDevices_InvalidDevice(t *testing.T) {
	ds := ExtensionDevices{}

	d := mustBuildExtensionDevice6Fields(t)
	d.CertificateChainDigest = nil

	require.EqualError(t, ds.Add(&d), "failed at index 0: certificate chain digest: missing mandatory field")
	require.Error(t, ds.Replace([]*ExtensionDevice{&d}), "failed at index 0: certificate chain digest: missing mandatory field")
}

func Test_ExtensionDevices_typed_nil_key(t *testing.T) {
	var key *ExtensionDevice = nil
	keys := ExtensionDevices{}
	err := keys.Add(key)

	assert.EqualError(t, err, "failed at index 0: Nil key in ExtensionDevices")
}
