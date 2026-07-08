package platform

import "github.com/veraison/psatoken"

// TBBRoTPKItem represents a single item in the CCA platform TBB ROTPK claim.
type TBBRoTPKItem struct {
	Name             *string `cbor:"1,keyasint" json:"description"`        // e.g. "CM" or "DM"
	ActiveArrayIndex *int32  `cbor:"2,keyasint" json:"active-array-index"` // active ROTPK array
	Index            *int32  `cbor:"3,keyasint" json:"index"`              // index in the active array
	Hash             *[]byte `cbor:"4,keyasint" json:"hash"`               // hash object
}

func (i TBBRoTPKItem) Validate() error {
	return ValidateTBBRoTPKItem(&i)
}

func (i TBBRoTPKItem) GetName() (string, error) {
	if i.Name == nil {
		return "", psatoken.ErrMandatoryFieldMissing
	}

	return *i.Name, nil
}

func (i TBBRoTPKItem) GetActiveRoTPKArray() (int32, error) {
	if i.ActiveArrayIndex == nil {
		return 0, psatoken.ErrMandatoryFieldMissing
	}

	return *i.ActiveArrayIndex, nil
}

func (i TBBRoTPKItem) GetIndex() (int32, error) {
	if i.Index == nil {
		return 0, psatoken.ErrMandatoryFieldMissing
	}

	return *i.Index, nil
}

func (i TBBRoTPKItem) GetHash() ([]byte, error) {
	if i.Hash == nil {
		return nil, psatoken.ErrMandatoryFieldMissing
	}

	if err := psatoken.ValidatePSAHashType(*i.Hash); err != nil {
		return nil, err
	}

	return *i.Hash, nil
}

func (i *TBBRoTPKItem) SetName(v string) error {
	i.Name = &v
	return nil
}

func (i *TBBRoTPKItem) SetActiveRoTPKArray(v int32) error {
	i.ActiveArrayIndex = &v
	return nil
}

func (i *TBBRoTPKItem) SetIndex(v int32) error {
	i.Index = &v
	return nil
}

func (i *TBBRoTPKItem) SetHash(v []byte) error {
	if err := psatoken.ValidatePSAHashType(v); err != nil {
		return err
	}

	i.Hash = &v

	return nil
}
