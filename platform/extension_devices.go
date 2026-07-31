// Copyright 2021-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"fmt"

	"github.com/veraison/psatoken"
)

type ExtensionDevices []*ExtensionDevice

func (o ExtensionDevices) Validate() error {
	if len(o) == 0 {
		return psatoken.ErrOptionalClaimMissing
	}

	return validateExtensionDevices(o)
}

func (o ExtensionDevices) Copy() (ExtensionDevices, error) {
	err := validateExtensionDevices(o)
	if err != nil {
		return nil, err
	}

	ret := make(ExtensionDevices, len(o))
	copy(ret, o)

	return ret, nil
}

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
