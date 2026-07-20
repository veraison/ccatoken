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
	GetProtocol() (Protocol, error)
	GetVCADigest() ([]byte, error)
	GetDeviceType() (DeviceType, error)
	GetEncryptionType() (EncryptionType, error)

	SetHashAlgorithm(v string) error
	SetDeviceMeasurementsDigest(v []byte) error
	SetCertificateChainDigest(v []byte) error
	SetUsesIDE(v bool) error
	SetProtocol(p Protocol) error
	SetVCADigest(v []byte) error
	SetDeviceType(t DeviceType) error
	SetEncryptionType(e EncryptionType) error
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
