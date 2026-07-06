package platform

// Where an implementation of the CCA platform follows the Trusted Board Boot specification [TBB],
// the platform will include several provisioned public key identifiers which are used to establish a chain of trust.
// The CCA platform TBB ROTPK claim is used to provide this information to a verifier.

// ITbbRotpkArray defines the interface for the CCA platform TBB ROTPK claim.
type ITbbRotpkArray interface {
	// Validate returns an error if any of the contained ITbbRotpkItem values
	// are invalid.
	Validate() error
	// Values returns a []ITbbRotpkItem of the contained values. An error may
	// be returned if any of the contained values are invalid.
	Values() ([]ITbbRotpkItem, error)
	// Add one or more ITbbRotpkItem's to the container. An error
	// may be returned if any of the values being added is invalid.
	Add(vals ...ITbbRotpkItem) error
	// Replace replaces the existing contents with the provided value. An error may be
	// returned if any of the new values are invalid.
	Replace(vals []ITbbRotpkItem) error
	// IsEmpty returns true if the container does not contain any values.
	IsEmpty() bool
}
