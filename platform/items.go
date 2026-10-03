// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"fmt"

	"github.com/veraison/psatoken"
)

func validateItems[T any, P interface {
	*T
	Validate() error
}](vals []P, claimName, typeName string) error {
	if len(vals) == 0 {
		return fmt.Errorf("%w: %s: is empty slice", psatoken.ErrWrongSyntax, claimName)
	}

	for i, k := range vals {
		if k == nil {
			return fmt.Errorf("failed at index %d: nil key in %s", i, typeName)
		}

		if err := k.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}

func copyItems[T any, P interface {
	*T
	Validate() error
}, S ~[]P](vals S, claimName, typeName string) (S, error) {
	if err := validateItems(vals, claimName, typeName); err != nil {
		return nil, err
	}

	ret := make(S, len(vals))
	copy(ret, vals)

	return ret, nil
}
