// Copyright 2021-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/psatoken"
)

const (
	testUsesIDE         bool       = true
	testOtherProtocol   Protocol   = "other-protocol-1.2.3"
	testOtherDeviceType DeviceType = "other-device-2"
)

func Test_ExtensionDevice_SetAndGetHashAlgorithm(t *testing.T) {
	d := ExtensionDevice{}

	require.NoError(t, d.SetHashAlgorithm(testHashAlgID))
	assert.Equal(t, testHashAlgID, *d.HashAlgorithm)
	ha, err := d.GetHashAlgorithm()
	require.NoError(t, err)
	assert.Equal(t, testHashAlgID, ha)
}

func Test_ExtensionDevice_SetAndGetDeviceMeasurementsDigest(t *testing.T) {
	d := ExtensionDevice{}
	require.NoError(t, d.SetDeviceMeasurementsDigest(testHash3))
	assert.Equal(t, testHash3, *d.DeviceMeasurementsDigest)
	dmd, err := d.GetDeviceMeasurementsDigest()
	require.NoError(t, err)
	assert.Equal(t, testHash3, dmd)

	err = d.SetDeviceMeasurementsDigest(testBadHash)
	assert.EqualError(t, err, "wrong syntax: length 36 (hash MUST be 32, 48 or 64 bytes)")
}

func Test_ExtensionDevice_SetAndGetCertificateChainDigest(t *testing.T) {
	d := ExtensionDevice{}

	require.NoError(t, d.SetCertificateChainDigest(testHash2))
	assert.Equal(t, testHash2, *d.CertificateChainDigest)
	ccd, err := d.GetCertificateChainDigest()
	require.NoError(t, err)
	assert.Equal(t, testHash2, ccd)

	err = d.SetCertificateChainDigest(testBadHash)
	assert.EqualError(t, err, "wrong syntax: length 36 (hash MUST be 32, 48 or 64 bytes)")
}

func Test_ExtensionDevice_SetAndGetUsesIDE(t *testing.T) {
	d := ExtensionDevice{}

	_, err := d.GetUsesIDE()
	assert.EqualError(t, err, "missing mandatory field")

	require.NoError(t, d.SetUsesIDE(true))
	assert.Equal(t, true, *d.UsesIDE)
	ide, err := d.GetUsesIDE()
	require.NoError(t, err)
	assert.Equal(t, true, ide)
}

func Test_ExtensionDevice_ProtocolWithVCADigest(t *testing.T) {
	d := ExtensionDevice{}

	err := d.SetProtocol(ProtocolSPDM140)
	require.NoError(t, err)

	err = d.SetVCADigest(testHash1)
	require.NoError(t, err)

	p, err := d.GetProtocol()
	require.NoError(t, err)
	assert.Equal(t, ProtocolSPDM140, p)

	digest, err := d.GetVCADigest()
	require.NoError(t, err)
	assert.Equal(t, testHash1, digest)
}

func Test_ExtensionDevice_ProtocolMissingVCADigest(t *testing.T) {
	d := ExtensionDevice{}

	err := d.SetProtocol(ProtocolSPDM140)
	require.NoError(t, err)

	_, err = d.GetProtocol()
	expectedErr := fmt.Errorf("protocol %s requires a VCA digest", ProtocolSPDM140)
	assert.EqualError(t, err, expectedErr.Error())

	_, err = d.GetVCADigest()
	assert.EqualError(t, err, expectedErr.Error())
}

func Test_ExtensionDevice_ProtocolNotRequiringVCADigest(t *testing.T) {
	d := ExtensionDevice{}

	err := d.SetProtocol(testOtherProtocol)
	require.NoError(t, err)

	err = d.SetVCADigest(testHash1)
	expectedErr := fmt.Errorf("%w: VCA digest is not expected for protocol %s", psatoken.ErrFieldNotInProfile, testOtherProtocol)
	assert.EqualError(t, err, expectedErr.Error())

	p2, err := d.GetProtocol()
	require.NoError(t, err)
	assert.Equal(t, testOtherProtocol, p2)

	_, err = d.GetVCADigest()
	expectedErr = fmt.Errorf("%w: VCA digest not expected for protocol %s", psatoken.ErrFieldNotInProfile, testOtherProtocol)
	assert.EqualError(t, err, expectedErr.Error())
}

func Test_ExtensionDevice_CannotResetProtocol(t *testing.T) {
	d := ExtensionDevice{}

	err := d.SetProtocol(ProtocolSPDM140)
	require.NoError(t, err)

	err = d.SetProtocol(ProtocolSPDM130)
	assert.EqualError(t, err, "protocol can only be set once and is already set to spdm-1.4.0")
}

func Test_ExtensionDevice_MustSetProtocolBeforeVCADigest(t *testing.T) {
	d := ExtensionDevice{}

	err := d.SetVCADigest(testHash1)
	assert.EqualError(t, err, "protocol must be set before setting VCA digest")
}

func Test_ExtensionDevice_DeviceTypeRequiringEncryptionType(t *testing.T) {
	d := ExtensionDevice{}

	err := d.SetDeviceType(DeviceTypeCXLType3)
	require.NoError(t, err)

	err = d.SetEncryptionType(HostSideEncryption)
	require.NoError(t, err)

	dt, err := d.GetDeviceType()
	require.NoError(t, err)
	assert.Equal(t, DeviceTypeCXLType3, dt)

	et, err := d.GetEncryptionType()
	require.NoError(t, err)
	assert.Equal(t, HostSideEncryption, et)

	err = d.SetEncryptionType(TargetSideEncryption)
	require.NoError(t, err)
	et, err = d.GetEncryptionType()
	require.NoError(t, err)
	assert.Equal(t, TargetSideEncryption, et)

	err = d.SetEncryptionType(NoEncryption)
	require.NoError(t, err)
	et, err = d.GetEncryptionType()
	require.NoError(t, err)
	assert.Equal(t, NoEncryption, et)
}

func Test_ExtensionDevice_DeviceTypeMissingEncryptionType(t *testing.T) {
	d := ExtensionDevice{}
	err := d.SetDeviceType(DeviceTypeCXLType3)
	require.NoError(t, err)

	_, err = d.GetDeviceType()
	expectedErr := fmt.Errorf("device type %s requires an encryption type", DeviceTypeCXLType3)
	assert.EqualError(t, err, expectedErr.Error())

	_, err = d.GetEncryptionType()
	assert.EqualError(t, err, expectedErr.Error())
}

func Test_ExtensionDevice_DeviceTypeNotRequiringEncryptionType(t *testing.T) {
	d := ExtensionDevice{}
	err := d.SetDeviceType(testOtherDeviceType)
	require.NoError(t, err)

	_, err = d.GetDeviceType()
	require.NoError(t, err)

	_, err = d.GetEncryptionType()
	expectedErr := fmt.Errorf("%w: encryption type not expected for device type %s", psatoken.ErrFieldNotInProfile, testOtherDeviceType)
	assert.EqualError(t, err, expectedErr.Error())

	dt2, err := d.GetDeviceType()
	require.NoError(t, err)
	assert.Equal(t, testOtherDeviceType, dt2)

	_, err = d.GetEncryptionType()
	expectedErr = fmt.Errorf("%w: encryption type not expected for device type %s", psatoken.ErrFieldNotInProfile, testOtherDeviceType)
	assert.EqualError(t, err, expectedErr.Error())
}

func Test_ExtensionDevice_CannotResetDeviceType(t *testing.T) {
	d := ExtensionDevice{}

	err := d.SetDeviceType(DeviceTypeCXLType3)
	require.NoError(t, err)

	err = d.SetDeviceType(testOtherDeviceType)
	expectedErr := fmt.Errorf("device type can only be set once and is already set to %s", DeviceTypeCXLType3)
	assert.EqualError(t, err, expectedErr.Error())
}

func Test_ExtensionDevice_MustSetDeviceTypeBeforeEncryptionType(t *testing.T) {
	d := ExtensionDevice{}
	err := d.SetEncryptionType(HostSideEncryption)
	assert.EqualError(t, err, "device type must be set before setting encryption type")
}

func mustBuildExtensionDevice8Fields(t *testing.T) ExtensionDevice {
	d := ExtensionDevice{}
	require.NoError(t, d.SetHashAlgorithm(testHashAlgID))
	require.NoError(t, d.SetDeviceMeasurementsDigest(testHash1))
	require.NoError(t, d.SetCertificateChainDigest(testHash2))
	require.NoError(t, d.SetUsesIDE(testUsesIDE))
	require.NoError(t, d.SetProtocol(ProtocolSPDM120))
	require.NoError(t, d.SetVCADigest(testHash3))
	require.NoError(t, d.SetDeviceType(DeviceTypeCXLType3))
	require.NoError(t, d.SetEncryptionType(HostSideEncryption))

	require.NoError(t, d.Validate())

	return d
}

func mustBuildExtensionDevice6Fields(t *testing.T) ExtensionDevice {
	d := ExtensionDevice{}
	require.NoError(t, d.SetHashAlgorithm(testHashAlgID))
	require.NoError(t, d.SetDeviceMeasurementsDigest(testHash1))
	require.NoError(t, d.SetCertificateChainDigest(testHash2))
	require.NoError(t, d.SetUsesIDE(testUsesIDE))
	require.NoError(t, d.SetProtocol(testOtherProtocol))
	require.NoError(t, d.SetDeviceType(testOtherDeviceType))

	require.NoError(t, d.Validate())

	return d
}
