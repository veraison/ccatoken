package platform

import (
	"encoding/json"
	"fmt"
)

// Trusted Board Boot Root of Trust Public Key claim
type TBBRoTPKItems []ITBBRoTPKItem

func (o TBBRoTPKItems) Validate() error {
	if len(o) == 0 {
		return fmt.Errorf("TBBRoTPKItems is included but empty")
	}

	for i, k := range o {
		if isNilTBBRoTPKItem(k) {
			return fmt.Errorf("failed at index %d: %s", i, "Nil key in TBBRoTPKItems")
		}

		if err := k.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}

func (o *TBBRoTPKItems) UnmarshalCBOR(v []byte) error {
	var vals []*TBBRoTPKItem

	if err := dm.Unmarshal(v, &vals); err != nil {
		return err
	}

	*o = tbbRoTPKItemsFromConcrete(vals)

	return nil
}

func (o *TBBRoTPKItems) UnmarshalJSON(v []byte) error {
	var vals []*TBBRoTPKItem

	if err := json.Unmarshal(v, &vals); err != nil {
		return err
	}

	*o = tbbRoTPKItemsFromConcrete(vals)

	return nil
}

func tbbRoTPKItemsFromConcrete(vals []*TBBRoTPKItem) TBBRoTPKItems {
	ret := make(TBBRoTPKItems, len(vals))

	for i, v := range vals {
		ret[i] = v
	}

	return ret
}
