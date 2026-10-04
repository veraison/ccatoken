// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

type TBBRoTPKItems []*TBBRoTPKItem

// Validate all items in the TBBRoTPKItems slice.
// Returns an error if validation fails for any of the items, or if the slice is empty.
func (o TBBRoTPKItems) Validate() error {
	return validateItems(o, "TBB RoTPK", "TBBRoTPKItems")
}

// Copy returns a shallow copy of the TBBRoTPKItems slice.
// It validates the items before copying, and returns an error if validation fails.
func (o TBBRoTPKItems) Copy() (TBBRoTPKItems, error) {
	return copyItems(o, "TBB RoTPK", "TBBRoTPKItems")
}

// IsEmpty returns true if the TBBRoTPKItems slice is empty.
func (o TBBRoTPKItems) IsEmpty() bool {
	return len(o) == 0
}
