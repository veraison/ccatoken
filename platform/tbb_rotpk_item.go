package platform

import "github.com/veraison/psatoken"

type TbbRotpkItem struct {
	Name        *string `cbor:"1,keyasint" json:"description"`
	ActiveArray *uint32 `cbor:"2,keyasint" json:"active-array"`
	Index       *uint32 `cbor:"3,keyasint" json:"index"`
	Hash        *[]byte `cbor:"4,keyasint" json:"hash"`
}

func (i TbbRotpkItem) GetName() (string, error) {
	if i.Name == nil {
		return "", psatoken.ErrMandatoryFieldMissing
	}

	return *i.Name, nil
}

func (i TbbRotpkItem) GetActiveArray() (uint32, error) {
	if i.ActiveArray == nil {
		return 0, psatoken.ErrMandatoryFieldMissing
	}

	return *i.ActiveArray, nil
}

func (i TbbRotpkItem) GetIndex() (uint32, error) {
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

func (i *TbbRotpkItem) SetActiveArray(v uint32) error {
	i.ActiveArray = &v
	return nil
}

func (i *TbbRotpkItem) SetIndex(v uint32) error {
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
