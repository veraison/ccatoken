package platform

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// TbbRotpkArray is the generic implementation of ITbbRotpkArray.
// This provides a container of concrete type for marshaling purposes.
type TbbRotpkArray[I ITbbRotpkItem] struct {
	values []I //nolint:structcheck
}

func (o TbbRotpkArray[I]) Validate() error {
	for i, item := range o.values {
		if err := item.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}

func (o TbbRotpkArray[I]) Values() ([]ITbbRotpkItem, error) {
	ret := make([]ITbbRotpkItem, len(o.values))

	for i, item := range o.values {
		if err := item.Validate(); err != nil {
			return nil, fmt.Errorf("failed at index %d: %w", i, err)
		}

		ret[i] = item
	}

	return ret, nil
}

func (o *TbbRotpkArray[I]) Add(vals ...ITbbRotpkItem) error {
	toAdd, err := validateAndConvertTbbRotpkItems[I](vals)
	if err != nil {
		return err
	}

	o.values = append(o.values, toAdd...)

	return nil
}

func (o *TbbRotpkArray[I]) Replace(vals []ITbbRotpkItem) error {
	newVals, err := validateAndConvertTbbRotpkItems[I](vals)
	if err != nil {
		return err
	}

	o.values = newVals

	return nil
}

func (o TbbRotpkArray[I]) IsEmpty() bool {
	return len(o.values) == 0
}

func (o TbbRotpkArray[I]) MarshalCBOR() ([]byte, error) {
	return em.Marshal(o.values)
}

func (o *TbbRotpkArray[I]) UnmarshalCBOR(v []byte) error {
	return dm.Unmarshal(v, &o.values)
}

func (o TbbRotpkArray[I]) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.values)
}

func (o *TbbRotpkArray[I]) UnmarshalJSON(v []byte) error {
	return json.Unmarshal(v, &o.values)
}

func validateAndConvertTbbRotpkItems[I ITbbRotpkItem](vals []ITbbRotpkItem) ([]I, error) {
	ret := make([]I, len(vals))

	for i, item := range vals {
		if err := item.Validate(); err != nil {
			return nil, fmt.Errorf("failed at index %d: %w", i, err)
		}

		typedItem, ok := item.(I)
		if !ok {
			return nil, fmt.Errorf("incorrect type at index %d; must be %s",
				i, reflect.TypeOf((*I)(nil)).Elem().String())
		}

		ret[i] = typedItem
	}

	return ret, nil
}
