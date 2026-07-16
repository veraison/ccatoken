package platform

import (
	"fmt"

	"github.com/veraison/psatoken"
)

type IExtensionDevice interface {
	Validate() error

	GetHashAlgorithm() (string, error)
	GetDeviceMeasurementsDigest() ([]byte, error)
	GetCertificateChainDigest() ([]byte, error)
	GetUsesIDE() (bool, error)
	GetProtocolAndVCADigest() (Protocol, []byte, error)
	GetDeviceTypeAndEncryptionType() (DeviceType, EncryptionType, error)

	SetHashAlgorithm(v string) error
	SetDeviceMeasurementsDigest(v []byte) error
	SetCertificateChainDigest(v []byte) error
	SetUsesIDE(v bool) error
	SetProtocolAndVCADigest(p Protocol, v []byte) error
	SetDeviceTypeAndEncryptionType(t DeviceType, e EncryptionType) error
}

func ValidateExtensionDevice(d IExtensionDevice) error {
	if err := psatoken.FilterError(d.GetHashAlgorithm()); err != nil {
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

	if _p, _, err := d.GetProtocolAndVCADigest(); psatoken.FilterError(_p, err) != nil {
		return fmt.Errorf("protocol and VCA digest: %w", err)
	}

	if _t, _, err := d.GetDeviceTypeAndEncryptionType(); psatoken.FilterError(_t, err) != nil {
		return fmt.Errorf("device type and encryption: %w", err)
	}

	return nil
}
