package platform

import "github.com/veraison/psatoken"

// TbbRotpkItem represents a single item in the CCA platform TBB ROTPK claim.
type TbbRotpkItem struct {
	Name             *string `cbor:"1,keyasint" json:"description"`  // e.g. "CM" or "DM"
	ActiveROTPKArray *int32  `cbor:"2,keyasint" json:"active-array"` // active ROTPK array
	Index            *int32  `cbor:"3,keyasint" json:"index"`        // index in the active array
	Hash             *[]byte `cbor:"4,keyasint" json:"hash"`         // hash object
}

func (i TbbRotpkItem) Validate() error {
	return ValidateTbbRotpkItem(&i)
}

func (i TbbRotpkItem) GetName() (string, error) {
	if i.Name == nil {
		return "", psatoken.ErrMandatoryFieldMissing
	}

	return *i.Name, nil
}

func (i TbbRotpkItem) GetActiveROTPKArray() (int32, error) {
	if i.ActiveROTPKArray == nil {
		return 0, psatoken.ErrMandatoryFieldMissing
	}

	return *i.ActiveROTPKArray, nil
}

func (i TbbRotpkItem) GetIndex() (int32, error) {
	if i.Index == nil {
		return 0, psatoken.ErrMandatoryFieldMissing
	}

	return *i.Index, nil
}

func (i TbbRotpkItem) GetHash() ([]byte, error) {
	if i.Hash == nil {
		return nil, psatoken.ErrMandatoryFieldMissing
	}

	if err := psatoken.ValidatePSAHashType(*i.Hash); err != nil {
		return nil, err
	}

	return *i.Hash, nil
}

func (i *TbbRotpkItem) SetName(v string) error {
	i.Name = &v
	return nil
}

func (i *TbbRotpkItem) SetActiveROTPKArray(v int32) error {
	i.ActiveROTPKArray = &v
	return nil
}

func (i *TbbRotpkItem) SetIndex(v int32) error {
	i.Index = &v
	return nil
}

func (i *TbbRotpkItem) SetHash(v []byte) error {
	if err := psatoken.ValidatePSAHashType(v); err != nil {
		return err
	}

	i.Hash = &v

	return nil
}
