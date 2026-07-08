package platform

// ITBBRoTPKItems defines the interface for a container of TBB ROTPK items,
// each implementing ITBBRoTPKItem.
type ITBBRoTPKItems interface {
	// Validate returns an error if any of the contained ITBBRoTPKItem values is invalid.
	Validate() error

	// Values returns a []ITBBRoTPKItem of the contained values. An error may be
	// returned if any of the contained values are invalid.
	Values() ([]ITBBRoTPKItem, error)

	// Add one or more ITBBRoTPKItem to the container, appending them to the
	// existing contents. An error may be returned if any of the values being
	// added are invalid.
	Add(vals ...ITBBRoTPKItem) error

	// Replace the existing contents with the provided value. An error may be
	// returned if any of the new values are invalid.
	Replace(vals []ITBBRoTPKItem) error

	// IsEmpty returns true if the container does not contain any values.
	IsEmpty() bool
}
