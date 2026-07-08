package platform

import (
	"fmt"
	"reflect"

	"github.com/veraison/psatoken"
)

// ITBBRoTPKItem defines the interface for a TBB ROTPK item.
type ITBBRoTPKItem interface {
	Validate() error

	GetName() (string, error)            // e.g. "CM" or "DM"
	GetActiveRoTPKArray() (int32, error) // active ROTPK array
	GetIndex() (int32, error)            // index in the active array
	GetHash() ([]byte, error)            // hash object

	SetName(v string) error
	SetActiveRoTPKArray(v int32) error
	SetIndex(v int32) error
	SetHash(v []byte) error
}

// ValidateTBBRoTPKItem returns an error if validation fails for any of the
// fields of a TBB ROTPK item.
func ValidateTBBRoTPKItem(i ITBBRoTPKItem) error {
	if err := psatoken.FilterError(i.GetName()); err != nil {
		return fmt.Errorf("description: %w", err)
	}

	if err := psatoken.FilterError(i.GetActiveRoTPKArray()); err != nil {
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

// isNilTBBRoTPKItem returns true if the given ITBBRoTPKItem is nil or a typed nil.
// Used to check for nil values in TBBRoTPKItems.
func isNilTBBRoTPKItem(k ITBBRoTPKItem) bool {
	if k == nil {
		return true
	}

	v := reflect.ValueOf(k)
	if v.Kind() == reflect.Ptr {
		return v.IsNil()
	}
	return false
}
