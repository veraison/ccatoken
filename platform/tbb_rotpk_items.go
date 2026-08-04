// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"fmt"

	"github.com/veraison/psatoken"
)

type TBBRoTPKItems []*TBBRoTPKItem

// Validate all items in the TBBRoTPKItems slice.
// Returns an error if validation fails for any of the items, or if the slice is empty.
func (o TBBRoTPKItems) Validate() error {
	if len(o) == 0 {
		return psatoken.ErrOptionalClaimMissing
	}

	return validateTBBRoTPKItems(o)
}

// Copy returns a shallow copy of the TBBRoTPKItems slice.
// It validates the items before copying, and returns an error if validation fails.
func (o TBBRoTPKItems) Copy() (TBBRoTPKItems, error) {
	err := validateTBBRoTPKItems(o)
	if err != nil {
		return nil, err
	}

	ret := make(TBBRoTPKItems, len(o))
	copy(ret, o)

	return ret, nil
}

// IsEmpty returns true if the TBBRoTPKItems slice is empty.
func (o TBBRoTPKItems) IsEmpty() bool {
	return len(o) == 0
}

func validateTBBRoTPKItems(vals TBBRoTPKItems) error {
	for i, k := range vals {
		if k == nil {
			return fmt.Errorf("failed at index %d: %s", i, "nil key in TBBRoTPKItems")
		}

		if err := k.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}
