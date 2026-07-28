package platform

import (
	"encoding/json"
	"fmt"
)

type ExtensionDevices struct {
	values []*ExtensionDevice
}

func (o ExtensionDevices) Validate() error {
	for i, k := range o.values {
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
	ret := make([]*ExtensionDevice, len(o.values))

	for i, k := range o.values {
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

	o.values = append(o.values, toAdd...)

	return nil
}

func (o *ExtensionDevices) Replace(vals []*ExtensionDevice) error {
	newVals, err := validateExtensionDevices(vals)
	if err != nil {
		return err
	}

	o.values = newVals

	return nil
}

func (o ExtensionDevices) IsEmpty() bool {
	return len(o.values) == 0
}

func (o ExtensionDevices) MarshalCBOR() ([]byte, error) {
	return em.Marshal(o.values)
}

func (o *ExtensionDevices) UnmarshalCBOR(v []byte) error {
	return dm.Unmarshal(v, &o.values)
}

func (o ExtensionDevices) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.values)
}

func (o *ExtensionDevices) UnmarshalJSON(v []byte) error {
	return json.Unmarshal(v, &o.values)
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
