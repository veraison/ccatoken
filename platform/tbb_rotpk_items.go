package platform

import (
	"encoding/json"
	"fmt"
)

// TBBRoTPKItems provides a container for marshaling purposes.
type TBBRoTPKItems struct {
	values []*TBBRoTPKItem
}

func (o TBBRoTPKItems) Validate() error {
	for i, k := range o.values {
		if k == nil {
			return fmt.Errorf("failed at index %d: %s", i, "Nil key in TBBRoTPKItems")
		}

		if err := k.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}

func (o TBBRoTPKItems) Values() ([]*TBBRoTPKItem, error) {
	ret := make([]*TBBRoTPKItem, len(o.values))

	for i, k := range o.values {
		if k == nil {
			return nil, fmt.Errorf("failed at index %d: %s", i, "Nil key in TBBRoTPKItems")
		}

		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("failed at index %d: %w", i, err)
		}

		ret[i] = k
	}

	return ret, nil
}

func (o *TBBRoTPKItems) Add(vals ...*TBBRoTPKItem) error {
	toAdd, err := validateTBBRoTPKItems(vals)
	if err != nil {
		return err
	}

	o.values = append(o.values, toAdd...)

	return nil
}

func (o *TBBRoTPKItems) Replace(vals []*TBBRoTPKItem) error {
	newVals, err := validateTBBRoTPKItems(vals)
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

func validateTBBRoTPKItems(vals []*TBBRoTPKItem) ([]*TBBRoTPKItem, error) {
	ret := make([]*TBBRoTPKItem, len(vals))

	for i, k := range vals {
		if k == nil {
			return nil, fmt.Errorf("failed at index %d: %s", i, "Nil key in TBBRoTPKItems")
		}

		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("failed at index %d: %w", i, err)
		}

		ret[i] = k
	}

	return ret, nil
}
