package ccatoken

import "errors"

var (
	ErrClaimUndefined        = errors.New("undefined claim")
	ErrOptionalClaimMissing  = errors.New("missing optional claim")
	ErrMandatoryClaimMissing = errors.New("missing mandatory claim")
	ErrWrongClaimSyntax      = errors.New("wrong syntax for claim")
	ErrWrongProfile          = errors.New("wrong profile")
)
