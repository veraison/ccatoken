// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

type ExtensionDevices []*ExtensionDevice

// Validate all items in the ExtensionDevices slice.
// Returns an error if validation fails for any of the items, or if the slice is empty.
func (o ExtensionDevices) Validate() error {
	return validateItems(o, "extension", "ExtensionDevices")
}

// Copy returns a shallow copy of the ExtensionDevices slice.
// It validates the items before copying, and returns an error if validation fails.
func (o ExtensionDevices) Copy() (ExtensionDevices, error) {
	return copyItems(o, "extension", "ExtensionDevices")
}

// IsEmpty returns true if the ExtensionDevices slice is empty.
func (o ExtensionDevices) IsEmpty() bool {
	return len(o) == 0
}
