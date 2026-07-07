package platform

import (
	"encoding/json"
	"fmt"
)

// Trusted Board Boot Root of Trust Public Key claim
type TBBRoTPKeys []ITBBRoTPKey

func (o TBBRoTPKeys) Validate() error {
	for i, k := range o {
		if isNilTBBRoTPKey(k) {
			return fmt.Errorf("failed at index %d: %s", i, "Nil key in TBBRoTPKeys")
		}

		if err := k.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}

func (o *TBBRoTPKeys) UnmarshalCBOR(v []byte) error {
	var vals []*TBBRoTPKey

	if err := dm.Unmarshal(v, &vals); err != nil {
		return err
	}

	*o = tbbRoTPKeysFromConcrete(vals)

	return nil
}

func (o *TBBRoTPKeys) UnmarshalJSON(v []byte) error {
	var vals []*TBBRoTPKey

	if err := json.Unmarshal(v, &vals); err != nil {
		return err
	}

	*o = tbbRoTPKeysFromConcrete(vals)

	return nil
}

func tbbRoTPKeysFromConcrete(vals []*TBBRoTPKey) TBBRoTPKeys {
	ret := make(TBBRoTPKeys, len(vals))

	for i, v := range vals {
		ret[i] = v
	}

	return ret
}
