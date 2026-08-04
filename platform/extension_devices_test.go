// Copyright 2021-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/psatoken"
)

func Test_ExtensionDevices_Validate(t *testing.T) {
	ds := ExtensionDevices{}
	d1 := mustBuildExtensionDeviceMinimalFields(t)
	d2 := mustBuildExtensionDeviceAllFields(t)
	d3 := mustBuildExtensionDeviceAllFields(t)
	require.NoError(t, d1.Validate())
	require.NoError(t, d2.Validate())
	require.NoError(t, d3.Validate())

	ds = append(ds, &d1, &d2, &d3)

	err := ds.Validate()
	assert.NoError(t, err)
}

func Test_ExtensionDevices_Copy(t *testing.T) {
	d1 := mustBuildExtensionDeviceMinimalFields(t)
	d2 := mustBuildExtensionDeviceAllFields(t)
	ds := ExtensionDevices{&d1, &d2}

	vals, err := ds.Copy()
	require.NoError(t, err)
	require.Equal(t, ExtensionDevices{&d1, &d2}, vals)

	vals[0] = nil
	assert.Equal(t, ExtensionDevices{nil, &d2}, vals)
	assert.Equal(t, ExtensionDevices{&d1, &d2}, ds)
}

func Test_ExtensionDevices_Validate_invalid_device(t *testing.T) {
	d := mustBuildExtensionDeviceMinimalFields(t)
	d.CertificateChainDigest = nil

	ds := ExtensionDevices{&d}
	err := ds.Validate()
	assert.EqualError(t, err, "failed at index 0: certificate chain digest: missing mandatory field")
}

func Test_ExtensionDevices_Validate_nil_key(t *testing.T) {
	keys := ExtensionDevices{nil}
	err := keys.Validate()

	assert.EqualError(t, err, "failed at index 0: nil key in ExtensionDevices")
}

func Test_ExtensionDevices_Validate_empty_key(t *testing.T) {
	keys := ExtensionDevices{{}}

	err := keys.Validate()

	assert.EqualError(t, err, "failed at index 0: device measurements digest: missing mandatory field")
}

func Test_ExtensionDevices_Validate_empty_array(t *testing.T) {
	ds := ExtensionDevices{}
	err := ds.Validate()
	assert.EqualError(t, err, psatoken.ErrOptionalClaimMissing.Error())
}

func Test_ExtensionDevices_codec_roundtrip(t *testing.T) {
	d1 := mustBuildExtensionDeviceMinimalFields(t)
	d2 := mustBuildExtensionDeviceAllFields(t)
	ds := ExtensionDevices{&d1, &d2}

	jsonBytes, err := json.Marshal(ds)
	require.NoError(t, err)

	var fromJSON ExtensionDevices
	require.NoError(t, json.Unmarshal(jsonBytes, &fromJSON))
	require.NoError(t, fromJSON.Validate())
	assert.Equal(t, ExtensionDevices{&d1, &d2}, fromJSON)

	cborBytes, err := em.Marshal(ds)
	require.NoError(t, err)

	var fromCBOR ExtensionDevices
	require.NoError(t, dm.Unmarshal(cborBytes, &fromCBOR))
	require.NoError(t, fromCBOR.Validate())
	assert.Equal(t, ExtensionDevices{&d1, &d2}, fromCBOR)
}
