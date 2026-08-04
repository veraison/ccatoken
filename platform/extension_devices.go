// Copyright 2021-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"fmt"

	"github.com/veraison/psatoken"
)

type ExtensionDevices []*ExtensionDevice

// Validate all items in the ExtensionDevices slice.
// Returns an error if validation fails for any of the items, or if the slice is empty.
func (o ExtensionDevices) Validate() error {
	if len(o) == 0 {
		return fmt.Errorf("%w: extension: is empty slice", psatoken.ErrWrongSyntax)
	}

	return validateExtensionDevices(o)
}

// Copy returns a shallow copy of the ExtensionDevices slice.
// It validates the items before copying, and returns an error if validation fails.
func (o ExtensionDevices) Copy() (ExtensionDevices, error) {
	err := o.Validate()
	if err != nil {
		return nil, err
	}

	ret := make(ExtensionDevices, len(o))
	copy(ret, o)

	return ret, nil
}

// IsEmpty returns true if the ExtensionDevices slice is empty.
func (o ExtensionDevices) IsEmpty() bool {
	return len(o) == 0
}

func validateExtensionDevices(vals ExtensionDevices) error {
	for i, k := range vals {
		if k == nil {
			return fmt.Errorf("failed at index %d: %s", i, "nil key in ExtensionDevices")
		}

		if err := k.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}
