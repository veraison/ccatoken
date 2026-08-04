// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"fmt"

	"github.com/veraison/psatoken"
)

// ExtensionDevice represents a single platform extension device in the CCA platform extension claim.
type ExtensionDevice struct {
	// HashAlgID (optional) identifies the hash algorithm used for the extension device's digest fields.
	HashAlgID *string `cbor:"1,keyasint,omitempty" json:"hash-algo-id,omitempty"`

	// DeviceMeasurementsDigest is the extension's device measurements exchange digest.
	DeviceMeasurementsDigest *[]byte `cbor:"2,keyasint" json:"device-measurements-digest"`

	// CertificateChainDigest is the extension device's certificate chain digest.
	CertificateChainDigest *[]byte `cbor:"3,keyasint" json:"certificate-chain-digest"`

	// UsesIDE indicates whether this extension device uses Integrity & Data Encryption.
	UsesIDE *bool `cbor:"4,keyasint" json:"uses-ide"`

	// Protocol identifies the protocol used to communicate with the extension device.
	Protocol *Protocol `cbor:"5,keyasint" json:"protocol"`

	// VCADigest is required when this extension device's Protocol is one of the protocols-support-vca, otherwise no VCADigest field is expected
	VCADigest *[]byte `cbor:"6,keyasint,omitempty" json:"vca-digest,omitempty"`

	// DeviceType identifies the type of this extension device.
	DeviceType *DeviceType `cbor:"7,keyasint" json:"device-type"`

	// EncryptionType is required when this extension device's DeviceType is cxl-type-3, otherwise no EncryptionType field is expected
	EncryptionType *EncryptionType `cbor:"8,keyasint,omitempty" json:"encryption-type,omitempty"`
}

// Validates that the given string is not empty.
func ValidateExtensionDeviceHashAlgID(v string) error {
	if v == "" {
		return fmt.Errorf("%w: empty string", psatoken.ErrWrongSyntax)
	}
	return nil
}

// Protocol used to communicate with an extension device.
type Protocol string

// Protocols supporting VCA
const (
	ProtocolSPDM120 Protocol = "spdm-1.2.0"
	ProtocolSPDM121 Protocol = "spdm-1.2.1"
	ProtocolSPDM122 Protocol = "spdm-1.2.2"
	ProtocolSPDM123 Protocol = "spdm-1.2.3"
	ProtocolSPDM130 Protocol = "spdm-1.3.0"
	ProtocolSPDM131 Protocol = "spdm-1.3.1"
	ProtocolSPDM132 Protocol = "spdm-1.3.2"
	ProtocolSPDM140 Protocol = "spdm-1.4.0"
)

// RequiresVCADigest returns true if Protocol is one of the strings specified in https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token-03#name-cca-platform-extension,
// meaning an extension device specifying this protocol must have a VCA digest.
func (p Protocol) RequiresVCADigest() bool {
	switch p {
	case ProtocolSPDM120,
		ProtocolSPDM121,
		ProtocolSPDM122,
		ProtocolSPDM123,
		ProtocolSPDM130,
		ProtocolSPDM131,
		ProtocolSPDM132,
		ProtocolSPDM140:
		return true
	default:
		return false
	}
}

// ValidateProtocolAndVCADigest validates the protocol and VCA digest fields of an extension device,
// as per https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token-03#name-cca-platform-extension.
func ValidateProtocolAndVCADigest(p *Protocol, v *[]byte) error {
	if p == nil {
		return fmt.Errorf("%w: protocol is required", psatoken.ErrMandatoryFieldMissing)
	}

	// Disallow empty string as protocol
	if *p == "" {
		return fmt.Errorf("%w: empty string", psatoken.ErrWrongSyntax)
	}

	if p.RequiresVCADigest() {
		if v == nil {
			return fmt.Errorf("%w: protocol %s requires a VCA digest", psatoken.ErrMandatoryFieldMissing, *p)
		}
		err := psatoken.ValidatePSAHashType(*v)
		if err != nil {
			return fmt.Errorf("%w: invalid VCA digest", psatoken.ErrWrongSyntax)
		}
	}

	if !p.RequiresVCADigest() && v != nil {
		return fmt.Errorf("%w: VCA digest is not expected for protocol %s", psatoken.ErrWrongSyntax, *p)
	}

	return nil
}

// DeviceType identifies the type of this extension device.
type DeviceType string

const (
	DeviceTypeCXLType3 DeviceType = "cxl-type-3"
)

// RequiresEncryptionType returns true if DeviceType is one of the strings specified in https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token-03#name-cca-platform-extension,
// meaning an extension device specifying this device type must have an encryption type.
func (t DeviceType) RequiresEncryptionType() bool {
	switch t {
	case DeviceTypeCXLType3:
		return true
	default:
		return false
	}
}

// EncryptionType identifies the type of encryption used with an extension device.
type EncryptionType int32

const (
	HostSideEncryption EncryptionType = iota
	TargetSideEncryption
	NoEncryption
)

// ValidateDeviceTypeAndEncryption validates the device type and encryption type fields of an extension device,
// as per https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token-03#name-cca-platform-extension.
func ValidateDeviceTypeAndEncryption(d *DeviceType, e *EncryptionType) error {
	if d == nil {
		return fmt.Errorf("%w: device type is required", psatoken.ErrMandatoryFieldMissing)
	}

	// Disallow empty string as device type
	if *d == "" {
		return fmt.Errorf("%w: empty string", psatoken.ErrWrongSyntax)
	}

	if d.RequiresEncryptionType() {
		if e == nil {
			return fmt.Errorf("%w: device type %s requires an encryption type", psatoken.ErrMandatoryFieldMissing, *d)
		}
		if *e != HostSideEncryption && *e != TargetSideEncryption && *e != NoEncryption {
			return fmt.Errorf("%w: invalid encryption type %d", psatoken.ErrWrongSyntax, *e)
		}
	}

	if !d.RequiresEncryptionType() && e != nil {
		return fmt.Errorf("%w: encryption type is not expected for device type %s", psatoken.ErrWrongSyntax, *d)
	}

	return nil
}

// Validate returns an error if validation fails for any of the fields.
func (d ExtensionDevice) Validate() error {
	if err := psatoken.FilterError(d.GetHashAlgID()); err != nil {
		return fmt.Errorf("hash algorithm: %w", err)
	}

	if err := psatoken.FilterError(d.GetDeviceMeasurementsDigest()); err != nil {
		return fmt.Errorf("device measurements digest: %w", err)
	}

	if err := psatoken.FilterError(d.GetCertificateChainDigest()); err != nil {
		return fmt.Errorf("certificate chain digest: %w", err)
	}

	if err := psatoken.FilterError(d.GetUsesIDE()); err != nil {
		return fmt.Errorf("usesIDE: %w", err)
	}

	if err := psatoken.FilterError(d.GetVCADigest()); err != nil {
		return fmt.Errorf("VCA digest: %w", err)
	}

	if err := psatoken.FilterError(d.GetProtocol()); err != nil {
		return fmt.Errorf("protocol: %w", err)
	}

	if err := psatoken.FilterError(d.GetEncryptionType()); err != nil {
		return fmt.Errorf("encryption type: %w", err)
	}

	if err := psatoken.FilterError(d.GetDeviceType()); err != nil {
		return fmt.Errorf("device type: %w", err)
	}
	return nil
}

func (d ExtensionDevice) GetHashAlgID() (string, error) {
	if d.HashAlgID == nil {
		return "", psatoken.ErrOptionalFieldMissing
	}
	if err := ValidateExtensionDeviceHashAlgID(*d.HashAlgID); err != nil {
		return "", err
	}

	return *d.HashAlgID, nil
}

func (d ExtensionDevice) GetDeviceMeasurementsDigest() ([]byte, error) {
	if d.DeviceMeasurementsDigest == nil {
		return nil, psatoken.ErrMandatoryFieldMissing
	}

	if err := psatoken.ValidatePSAHashType(*d.DeviceMeasurementsDigest); err != nil {
		return nil, err
	}

	return *d.DeviceMeasurementsDigest, nil
}

func (d ExtensionDevice) GetCertificateChainDigest() ([]byte, error) {
	if d.CertificateChainDigest == nil {
		return nil, psatoken.ErrMandatoryFieldMissing
	}

	if err := psatoken.ValidatePSAHashType(*d.CertificateChainDigest); err != nil {
		return nil, err
	}

	return *d.CertificateChainDigest, nil
}

func (d ExtensionDevice) GetUsesIDE() (bool, error) {
	if d.UsesIDE == nil {
		return false, psatoken.ErrMandatoryFieldMissing
	}

	return *d.UsesIDE, nil
}

// GetProtocol validates the protocol and VCA digest fields of an extension device,
// as per https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token-03#name-cca-platform-extension, and returns the protocol if valid.
func (d ExtensionDevice) GetProtocol() (Protocol, error) {
	err := ValidateProtocolAndVCADigest(d.Protocol, d.VCADigest)
	if err != nil {
		return "", err
	}

	return *d.Protocol, nil
}

// GetVCADigest validates the protocol and VCA digest fields of an extension device,
// as per https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token-03#name-cca-platform-extension, and returns the VCA digest if valid.
func (d ExtensionDevice) GetVCADigest() ([]byte, error) {
	err := ValidateProtocolAndVCADigest(d.Protocol, d.VCADigest)
	if err != nil {
		return nil, err
	}

	if !d.Protocol.RequiresVCADigest() {
		return nil, fmt.Errorf("%w: VCA digest not expected for protocol %s", psatoken.ErrFieldNotInProfile, *d.Protocol)
	}

	return *d.VCADigest, nil
}

// GetDeviceType validates the device type and encryption type fields of an extension device,
// as per https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token-03#name-cca-platform-extension, and returns the device type if valid.
func (d ExtensionDevice) GetDeviceType() (DeviceType, error) {
	err := ValidateDeviceTypeAndEncryption(d.DeviceType, d.EncryptionType)
	if err != nil {
		return "", err
	}

	return *d.DeviceType, nil
}

// GetEncryptionType validates the device type and encryption type fields of an extension device,
// as per https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token-03#name-cca-platform-extension, and returns the encryption type if valid.
func (d ExtensionDevice) GetEncryptionType() (EncryptionType, error) {
	err := ValidateDeviceTypeAndEncryption(d.DeviceType, d.EncryptionType)
	if err != nil {
		return 0, err
	}

	if !d.DeviceType.RequiresEncryptionType() {
		return 0, fmt.Errorf("%w: encryption type not expected for device type %s", psatoken.ErrFieldNotInProfile, *d.DeviceType)
	}

	return *d.EncryptionType, nil
}

func (d *ExtensionDevice) SetHashAlgID(v string) error {
	if err := ValidateExtensionDeviceHashAlgID(v); err != nil {
		return err
	}

	d.HashAlgID = &v
	return nil
}

func (d *ExtensionDevice) SetDeviceMeasurementsDigest(v []byte) error {
	if err := psatoken.ValidatePSAHashType(v); err != nil {
		return err
	}
	d.DeviceMeasurementsDigest = &v
	return nil
}

func (d *ExtensionDevice) SetCertificateChainDigest(v []byte) error {
	if err := psatoken.ValidatePSAHashType(v); err != nil {
		return err
	}
	d.CertificateChainDigest = &v
	return nil
}

func (d *ExtensionDevice) SetUsesIDE(v bool) error {
	d.UsesIDE = &v
	return nil
}

// SetProtocol can only be called once. If the protocol is already set, an error is returned.
// This prevents changes in whether a VCA digest is required or not.
// See https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token-03#name-cca-platform-extension for which protocols require a VCA digest.
func (d *ExtensionDevice) SetProtocol(p Protocol) error {
	if d.Protocol != nil {
		return fmt.Errorf("protocol can only be set once and is already set to %s", *d.Protocol)
	}
	if p == "" {
		return fmt.Errorf("%w: empty string", psatoken.ErrWrongSyntax)
	}
	d.Protocol = &p

	return nil
}

// SetVCADigest can only be set after the protocol has been set, and only if the protocol requires a VCA digest.
// If the protocol does not require a VCA digest, an error is returned.
// See https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token-03#name-cca-platform-extension for which protocols require a VCA digest.
func (d *ExtensionDevice) SetVCADigest(h []byte) error {
	if d.Protocol == nil {
		return fmt.Errorf("protocol must be set before setting VCA digest")
	}

	if !d.Protocol.RequiresVCADigest() {
		return fmt.Errorf("%w: VCA digest is not expected for protocol %s", psatoken.ErrFieldNotInProfile, *d.Protocol)
	}

	err := ValidateProtocolAndVCADigest(d.Protocol, &h)
	if err != nil {
		return err
	}

	d.VCADigest = &h

	return nil
}

// SetDeviceType can only be called once. If the device type is already set, an error is returned.
// This prevents changes in whether an encryption type is required or not.
// See https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token-03#name-cca-platform-extension for which device types require encryption type.
func (d *ExtensionDevice) SetDeviceType(t DeviceType) error {
	if d.DeviceType != nil {
		return fmt.Errorf("device type can only be set once and is already set to %s", *d.DeviceType)
	}
	if t == "" {
		return fmt.Errorf("%w: empty string", psatoken.ErrWrongSyntax)
	}

	d.DeviceType = &t

	return nil
}

// SetEncryptionType can only be called after the device type has been set, and only if the device type requires an encryption type.
// If the device type does not require an encryption type, an error is returned.
// See https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token-03#name-cca-platform-extension for which device types require encryption type.
func (d *ExtensionDevice) SetEncryptionType(t EncryptionType) error {
	if d.DeviceType == nil {
		return fmt.Errorf("device type must be set before setting encryption type")
	}

	if !d.DeviceType.RequiresEncryptionType() {
		return fmt.Errorf("%w: encryption type is not expected for device type %s", psatoken.ErrFieldNotInProfile, *d.DeviceType)
	}

	if t != HostSideEncryption && t != TargetSideEncryption && t != NoEncryption {
		return fmt.Errorf("invalid encryption type: %d", t)
	}

	d.EncryptionType = &t

	return nil
}
