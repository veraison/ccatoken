package platform

import (
	"fmt"

	"github.com/veraison/psatoken"
)

type ExtensionDevice struct {
	// HashAlgorithm identifies the hash algorithm used for the digest fields
	HashAlgorithm            *string `cbor:"1,keyasint,omitempty" json:"hashAlgorithm,omitempty"`
	DeviceMeasurementsDigest *[]byte `cbor:"2,keyasint" json:"deviceMeasurementsDigest"`
	CertificateChainDigest   *[]byte `cbor:"3,keyasint" json:"certificateChainDigest"`

	// UsesIDE indicates whether the platform device uses Integrity & Data Encryption.
	UsesIDE *bool `cbor:"4,keyasint" json:"usesIDE"`

	// Protocol identifies the protocol used to communicate with the device.
	Protocol *Protocol `cbor:"5,keyasint" json:"protocol"`

	// VCADigest is required when Protocol is one of the protocols-support-vca, otherwise no VCADigest field is expected
	VCADigest *[]byte `cbor:"6,keyasint,omitempty" json:"vcaDigest,omitempty"`

	// DeviceType identifies the type of platform extension device.
	DeviceType *DeviceType `cbor:"7,keyasint" json:"deviceType"`

	// EncryptionType is required for cxl-type-3, otherwise no EncryptionType field is expected
	EncryptionType *EncryptionType `cbor:"8,keyasint,omitempty" json:"encryptionType,omitempty"`
}

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

// Protocols supporting VCA require a VCA digest.
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

func ValidateProtocolAndVCADigest(p *Protocol, v *[]byte) error {
	if p == nil {
		return fmt.Errorf("protocol is required")
	}

	if p.RequiresVCADigest() {
		if v == nil {
			return fmt.Errorf("protocol %s requires a VCA digest", *p)
		}
		err := psatoken.ValidatePSAHashType(*v)
		if err != nil {
			return fmt.Errorf("invalid VCA digest: %w", err)
		}
	}

	if !p.RequiresVCADigest() && v != nil {
		return fmt.Errorf("VCA digest is not expected for protocol %s", *p)
	}

	return nil
}

// DeviceType identifies the type of platform extension device.
type DeviceType string

const (
	DeviceTypeCXLType3 DeviceType = "cxl-type-3"
)

func (t DeviceType) RequiresEncryptionType() bool {
	switch t {
	case DeviceTypeCXLType3:
		return true
	default:
		return false
	}
}

type EncryptionType int32

const (
	HostSideEncryption EncryptionType = iota
	TargetSideEncryption
	NoEncryption
)

func (d ExtensionDevice) Validate() error {
	return ValidateExtensionDevice(&d)
}

func ValidateDeviceTypeAndEncryption(d *DeviceType, e *EncryptionType) error {
	if d == nil {
		return fmt.Errorf("device type is required")
	}

	if d.RequiresEncryptionType() {
		if e == nil {
			return fmt.Errorf("device type %s requires an encryption type", *d)
		}
		if *e != HostSideEncryption && *e != TargetSideEncryption && *e != NoEncryption {
			return fmt.Errorf("invalid encryption type %s", *d)
		}
	}

	if !d.RequiresEncryptionType() && e != nil {
		return fmt.Errorf("encryption type is not expected for device type %s", *d)
	}

	return nil
}

func (d ExtensionDevice) GetHashAlgorithm() (string, error) {
	if d.HashAlgorithm == nil {
		return "", psatoken.ErrMandatoryFieldMissing
	}

	return *d.HashAlgorithm, nil
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

func (d ExtensionDevice) GetProtocol() (Protocol, error) {
	err := ValidateProtocolAndVCADigest(d.Protocol, d.VCADigest)
	if err != nil {
		return "", err
	}

	return *d.Protocol, nil
}

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

func (d ExtensionDevice) GetDeviceType() (DeviceType, error) {
	err := ValidateDeviceTypeAndEncryption(d.DeviceType, d.EncryptionType)
	if err != nil {
		return "", err
	}

	return *d.DeviceType, nil
}

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

func (d *ExtensionDevice) SetHashAlgorithm(v string) error {
	d.HashAlgorithm = &v
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

// Protocol can only be set once. If it is already set, return an error.
// This is to keep the validation logic for protocol and VCA digest simple.
func (d *ExtensionDevice) SetProtocol(p Protocol) error {
	if d.Protocol != nil {
		return fmt.Errorf("protocol can only be set once and is already set to %s", *d.Protocol)
	}
	d.Protocol = &p

	return nil
}

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

// Device type can only be set once. If it is already set, return an error.
// This is to keep the validation logic for device type and encryption type simple.
func (d *ExtensionDevice) SetDeviceType(t DeviceType) error {
	if d.DeviceType != nil {
		return fmt.Errorf("device type can only be set once and is already set to %s", *d.DeviceType)
	}

	d.DeviceType = &t

	return nil
}

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
