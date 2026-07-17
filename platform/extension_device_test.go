package platform

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/psatoken"
)

func Test_ExtensionDevice_SetAndGetHashAlgorithm(t *testing.T) {
	d := ExtensionDevice{}

	require.NoError(t, d.SetHashAlgorithm("SHA-256"))
	assert.Equal(t, "SHA-256", *d.HashAlgorithm)
	ha, err := d.GetHashAlgorithm()
	require.NoError(t, err)
	assert.Equal(t, "SHA-256", ha)
}

func Test_ExtensionDevice_SetAndGetDeviceMeasurementsDigest(t *testing.T) {
	d := ExtensionDevice{}
	hash := mustHexDecode(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	badHash := mustHexDecode(t, "0123")

	require.NoError(t, d.SetDeviceMeasurementsDigest(hash))
	assert.Equal(t, hash, *d.DeviceMeasurementsDigest)
	dmd, err := d.GetDeviceMeasurementsDigest()
	require.NoError(t, err)
	assert.Equal(t, hash, dmd)

	err = d.SetDeviceMeasurementsDigest(badHash)
	assert.EqualError(t, err, "wrong syntax: length 2 (hash MUST be 32, 48 or 64 bytes)")
}

func Test_ExtensionDevice_SetAndGetCertificateChainDigest(t *testing.T) {
	d := ExtensionDevice{}
	hash := mustHexDecode(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	badHash := mustHexDecode(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefabcdef")

	require.NoError(t, d.SetCertificateChainDigest(hash))
	assert.Equal(t, hash, *d.CertificateChainDigest)
	ccd, err := d.GetCertificateChainDigest()
	require.NoError(t, err)
	assert.Equal(t, hash, ccd)

	err = d.SetCertificateChainDigest(badHash)
	assert.EqualError(t, err, "wrong syntax: length 35 (hash MUST be 32, 48 or 64 bytes)")
}

func Test_ExtensionDevice_SetAndGetUsesIDE(t *testing.T) {
	d := ExtensionDevice{}

	ide, err := d.GetUsesIDE()
	assert.EqualError(t, err, "missing mandatory field")

	require.NoError(t, d.SetUsesIDE(true))
	assert.Equal(t, true, *d.UsesIDE)
	ide, err = d.GetUsesIDE()
	require.NoError(t, err)
	assert.Equal(t, true, ide)
}

func Test_ExtensionDevice_ProtocolWithVCADigest(t *testing.T) {
	hash := mustHexDecode(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	d := ExtensionDevice{}

	err := d.SetProtocol(ProtocolSPDM140)
	require.NoError(t, err)

	err = d.SetVCADigest(hash)
	require.NoError(t, err)

	p, err := d.GetProtocol()
	require.NoError(t, err)
	assert.Equal(t, ProtocolSPDM140, p)

	digest, err := d.GetVCADigest()
	require.NoError(t, err)
	assert.Equal(t, hash, digest)
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
	hash := mustHexDecode(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	d := ExtensionDevice{}

	var p Protocol = "other-protocol-1.2.3"

	err := d.SetProtocol(p)
	require.NoError(t, err)

	err = d.SetVCADigest(hash)
	expectedErr := fmt.Errorf("%w: VCA digest is not expected for protocol %s", psatoken.ErrFieldNotInProfile, p)
	assert.EqualError(t, err, expectedErr.Error())

	p2, err := d.GetProtocol()
	require.NoError(t, err)
	assert.Equal(t, p, p2)

	_, err = d.GetVCADigest()
	expectedErr = fmt.Errorf("%w: VCA digest not expected for protocol %s", psatoken.ErrFieldNotInProfile, p)
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
	hash := mustHexDecode(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	err := d.SetVCADigest(hash)
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

	d.SetEncryptionType(TargetSideEncryption)
	et, err = d.GetEncryptionType()
	require.NoError(t, err)
	assert.Equal(t, TargetSideEncryption, et)

	d.SetEncryptionType(NoEncryption)
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
	var dt DeviceType = "other-device-type-2"
	d.SetDeviceType(dt)

	_, err := d.GetDeviceType()
	require.NoError(t, err)

	_, err = d.GetEncryptionType()
	expectedErr := fmt.Errorf("%w: encryption type not expected for device type %s", psatoken.ErrFieldNotInProfile, dt)
	assert.EqualError(t, err, expectedErr.Error())

	dt2, err := d.GetDeviceType()
	require.NoError(t, err)
	assert.Equal(t, dt, dt2)

	_, err = d.GetEncryptionType()
	expectedErr = fmt.Errorf("%w: encryption type not expected for device type %s", psatoken.ErrFieldNotInProfile, dt)
	assert.EqualError(t, err, expectedErr.Error())
}

func Test_ExtensionDevice_CannotResetDeviceType(t *testing.T) {
	d := ExtensionDevice{}
	var dt DeviceType = "other-device-type-2"

	err := d.SetDeviceType(DeviceTypeCXLType3)
	require.NoError(t, err)

	err = d.SetDeviceType(dt)
	expectedErr := fmt.Errorf("device type can only be set once and is already set to %s", DeviceTypeCXLType3)
	assert.EqualError(t, err, expectedErr.Error())
}

func Test_ExtensionDevice_MustSetDeviceTypeBeforeEncryptionType(t *testing.T) {
	d := ExtensionDevice{}
	err := d.SetEncryptionType(HostSideEncryption)
	assert.EqualError(t, err, "device type must be set before setting encryption type")
}
