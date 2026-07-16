package platform

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// ExtensionDevices is the standard implementation of IExtensionDevices interface that
// should suffice for most purposes. This provides a container of concrete types
// for marshaling purposes.
type ExtensionDevices struct {
	values []*ExtensionDevice
}

func (o ExtensionDevices) Validate() error {
	for i, k := range o.values {
		if isNilExtensionDevice(k) {
			return fmt.Errorf("failed at index %d: %s", i, "Nil key in ExtensionDevices")
		}

		if err := k.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}

func (o ExtensionDevices) Values() ([]IExtensionDevice, error) {
	ret := make([]IExtensionDevice, len(o.values))

	for i, k := range o.values {
		if isNilExtensionDevice(k) {
			return nil, fmt.Errorf("failed at index %d: %s", i, "Nil key in ExtensionDevices")
		}

		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("failed at index %d: %w", i, err)
		}

		ret[i] = k
	}

	return ret, nil
}

func (o *ExtensionDevices) Add(vals ...IExtensionDevice) error {
	toAdd, err := validateAndConvertExtensionDevices(vals)
	if err != nil {
		return err
	}

	o.values = append(o.values, toAdd...)

	return nil
}

func (o *ExtensionDevices) Replace(vals []IExtensionDevice) error {
	newVals, err := validateAndConvertExtensionDevices(vals)
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

func validateAndConvertExtensionDevices(vals []IExtensionDevice) ([]*ExtensionDevice, error) {
	ret := make([]*ExtensionDevice, len(vals))

	for i, k := range vals {
		if isNilExtensionDevice(k) {
			return nil, fmt.Errorf("failed at index %d: %s", i, "Nil key in ExtensionDevices")
		}

		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("failed at index %d: %w", i, err)
		}

		ta, ok := k.(*ExtensionDevice)
		if !ok {
			return nil, fmt.Errorf("incorrect type at index %d; must be %s",
				i, reflect.TypeOf(ExtensionDevice{}).Name())
		}

		ret[i] = ta
	}

	return ret, nil
}
