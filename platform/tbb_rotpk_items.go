package platform

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// TBBRoTPKItems is the standard implementation of ITBBRoTPKItems interface that
// should suffice for most purposes. This provides a container of concrete types
// for marshaling purposes.
type TBBRoTPKItems struct {
	values []*TBBRoTPKItem
}

func (o TBBRoTPKItems) Validate() error {
	for i, k := range o.values {
		if isNilTBBRoTPKItem(k) {
			return fmt.Errorf("failed at index %d: %s", i, "Nil key in TBBRoTPKItems")
		}

		if err := k.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}

func (o TBBRoTPKItems) Values() ([]ITBBRoTPKItem, error) {
	ret := make([]ITBBRoTPKItem, len(o.values))

	for i, k := range o.values {
		if isNilTBBRoTPKItem(k) {
			return nil, fmt.Errorf("failed at index %d: %s", i, "Nil key in TBBRoTPKItems")
		}

		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("failed at index %d: %w", i, err)
		}

		ret[i] = k
	}

	return ret, nil
}

func (o *TBBRoTPKItems) Add(vals ...ITBBRoTPKItem) error {
	toAdd, err := validateAndConvertTBBRoTPKItems(vals)
	if err != nil {
		return err
	}

	o.values = append(o.values, toAdd...)

	return nil
}

func (o *TBBRoTPKItems) Replace(vals []ITBBRoTPKItem) error {
	newVals, err := validateAndConvertTBBRoTPKItems(vals)
	if err != nil {
		return err
	}

	o.values = newVals

	return nil
}

func (o TBBRoTPKItems) IsEmpty() bool {
	return len(o.values) == 0
}

func (o TBBRoTPKItems) MarshalCBOR() ([]byte, error) {
	return em.Marshal(o.values)
}

func (o *TBBRoTPKItems) UnmarshalCBOR(v []byte) error {
	return dm.Unmarshal(v, &o.values)
}

func (o TBBRoTPKItems) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.values)
}

func (o *TBBRoTPKItems) UnmarshalJSON(v []byte) error {
	return json.Unmarshal(v, &o.values)
}

func validateAndConvertTBBRoTPKItems(vals []ITBBRoTPKItem) ([]*TBBRoTPKItem, error) {
	ret := make([]*TBBRoTPKItem, len(vals))

	for i, k := range vals {
		if isNilTBBRoTPKItem(k) {
			return nil, fmt.Errorf("failed at index %d: %s", i, "Nil key in TBBRoTPKItems")
		}

		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("failed at index %d: %w", i, err)
		}

		ta, ok := k.(*TBBRoTPKItem)
		if !ok {
			return nil, fmt.Errorf("incorrect type at index %d; must be %s",
				i, reflect.TypeOf(TBBRoTPKItem{}).Name())
		}

		ret[i] = ta
	}

	return ret, nil
}
