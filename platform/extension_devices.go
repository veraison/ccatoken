package platform

import (
	"fmt"
)

type ExtensionDevices []*ExtensionDevice

func (o ExtensionDevices) Validate() error {
	for i, k := range o {
		if k == nil {
			return fmt.Errorf("failed at index %d: %s", i, "Nil key in ExtensionDevices")
		}

		if err := k.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}

func (o ExtensionDevices) Values() ([]*ExtensionDevice, error) {
	ret := make([]*ExtensionDevice, len(o))

	for i, k := range o {
		if k == nil {
			return nil, fmt.Errorf("failed at index %d: %s", i, "Nil key in ExtensionDevices")
		}

		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("failed at index %d: %w", i, err)
		}

		ret[i] = k
	}

	return ret, nil
}

func (o *ExtensionDevices) Add(vals ...*ExtensionDevice) error {
	toAdd, err := validateExtensionDevices(vals)
	if err != nil {
		return err
	}

	*o = append(*o, toAdd...)

	return nil
}

func (o *ExtensionDevices) Replace(vals []*ExtensionDevice) error {
	newVals, err := validateExtensionDevices(vals)
	if err != nil {
		return err
	}

	*o = newVals

	return nil
}

func (o ExtensionDevices) IsEmpty() bool {
	return len(o) == 0
}

func validateExtensionDevices(vals []*ExtensionDevice) ([]*ExtensionDevice, error) {
	ret := make([]*ExtensionDevice, len(vals))

	for i, k := range vals {
		if k == nil {
			return nil, fmt.Errorf("failed at index %d: %s", i, "Nil key in ExtensionDevices")
		}

		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("failed at index %d: %w", i, err)
		}

		ret[i] = k
	}

	return ret, nil
}
