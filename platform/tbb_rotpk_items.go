// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"fmt"

	"github.com/veraison/psatoken"
)

type TBBRoTPKItems []*TBBRoTPKItem

func (o TBBRoTPKItems) Validate() error {
	if len(o) == 0 {
		return psatoken.ErrOptionalClaimMissing
	}

	for i, k := range o {
		if k == nil {
			return fmt.Errorf("failed at index %d: %s", i, "Nil key in TBBRoTPKItems")
		}

		if err := k.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}

func (o TBBRoTPKItems) Values() (TBBRoTPKItems, error) {
	err := validateTBBRoTPKItems(o)
	if err != nil {
		return nil, err
	}

	ret := make(TBBRoTPKItems, len(o))
	copy(ret, o)

	return ret, nil
}

func (o *TBBRoTPKItems) Add(vals ...*TBBRoTPKItem) error {
	err := validateTBBRoTPKItems(vals)
	if err != nil {
		return err
	}

	*o = append(*o, vals...)

	return nil
}

func (o *TBBRoTPKItems) Replace(vals TBBRoTPKItems) error {
	err := validateTBBRoTPKItems(vals)
	if err != nil {
		return err
	}

	*o = vals

	return nil
}

func (o TBBRoTPKItems) IsEmpty() bool {
	return len(o) == 0
}

func validateTBBRoTPKItems(vals TBBRoTPKItems) error {
	for i, k := range vals {
		if k == nil {
			return fmt.Errorf("failed at index %d: %s", i, "Nil key in TBBRoTPKItems")
		}

		if err := k.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}
