package platform

import (
	"fmt"

	"github.com/veraison/psatoken"
)

// ITbbRotpkItem defines the interface for a TBB ROTPK item.
type ITbbRotpkItem interface {
	Validate() error

	GetName() (string, error)            // e.g. "CM" or "DM"
	GetActiveROTPKArray() (int32, error) // active ROTPK array
	GetIndex() (int32, error)            // index in the active array
	GetHash() ([]byte, error)            // hash object

	SetName(v string) error
	SetActiveROTPKArray(v int32) error
	SetIndex(v int32) error
	SetHash(v []byte) error
}

// ValidateTbbRotpkItem returns an error if validation fails for any of the
// fields of a TBB ROTPK item.
func ValidateTbbRotpkItem(i ITbbRotpkItem) error {
	if err := psatoken.FilterError(i.GetName()); err != nil {
		return fmt.Errorf("description: %w", err)
	}

	if err := psatoken.FilterError(i.GetActiveROTPKArray()); err != nil {
		return fmt.Errorf("active array: %w", err)
	}

	if err := psatoken.FilterError(i.GetIndex()); err != nil {
		return fmt.Errorf("index: %w", err)
	}

	if err := psatoken.FilterError(i.GetHash()); err != nil {
		return fmt.Errorf("hash: %w", err)
	}

	return nil
}
