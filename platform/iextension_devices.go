package platform

import "reflect"

// IExtensionDevices defines the interface for a container of extension devices,
// each implementing IExtensionDevice.
type IExtensionDevices interface {
	// Validate returns an error if any of the contained IExtensionDevice values is invalid.
	Validate() error

	// Values returns a []IExtensionDevice of the contained values. An error may be
	// returned if any of the contained values are invalid.
	Values() ([]IExtensionDevice, error)

	// Add one or more IExtensionDevice to the container, appending them to the
	// existing contents. An error may be returned if any of the values being
	// added are invalid.
	Add(vals ...IExtensionDevice) error

	// Replace the existing contents with the provided value. An error may be
	// returned if any of the new values are invalid.
	Replace(vals []IExtensionDevice) error

	// IsEmpty returns true if the container does not contain any values.
	IsEmpty() bool
}

// isNilExtensionDevice returns true if the given IExtensionDevice is nil or a typed nil.
// Used to check for nil values in ExtensionDevices.
func isNilExtensionDevice(k IExtensionDevice) bool {
	if k == nil {
		return true
	}

	v := reflect.ValueOf(k)
	if v.Kind() == reflect.Ptr {
		return v.IsNil()
	}
	return false
}
