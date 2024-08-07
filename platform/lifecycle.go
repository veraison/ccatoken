// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"fmt"

	"github.com/veraison/psatoken"
)

const (
	LifecycleUnknownMin                     = 0x0000
	LifecycleUnknownMax                     = 0x00ff
	LifecycleAssemblyAndTestMin             = 0x1000
	LifecycleAssemblyAndTestMax             = 0x10ff
	LifecycleRotProvisioningMin             = 0x2000
	LifecycleRotProvisioningMax             = 0x20ff
	LifecycleSecuredMin                     = 0x3000
	LifecycleSecuredMax                     = 0x30ff
	LifecycleNonCCAPlatformDebugMin         = 0x4000
	LifecycleNonCCAPlatformDebugMax         = 0x40ff
	LifecycleRecoverableCCAPlatformDebugMin = 0x5000
	LifecycleRecoverableCCAPlatformDebugMax = 0x50ff
	LifecycleDecommissionedMin              = 0x6000
	LifecycleDecommissionedMax              = 0x60ff
)

// LifeCycleState indicates the life cycle state of attested device. The state
// is derived from the life cycle claim value, with a range of values mapping
// onto each state.
type LifeCycleState uint16

const (
	StateUnknown LifeCycleState = iota
	StateAssemblyAndTest
	StateCCARotProvisioning
	StateSecured
	StateNonCCAPlatformDebug
	StateRecoverableCCAPlatformDebug
	StateDecommissioned

	StateInvalid // must be last
)

// IsValid returns true if the LifeCycleState has a valid value.
func (o LifeCycleState) IsValid() bool {
	return o < StateInvalid
}

// String returns a string representation of the life cycle state.
func (o LifeCycleState) String() string {
	switch o {
	case StateUnknown:
		return "unknown"
	case StateAssemblyAndTest:
		return "assembly-and-test"
	case StateCCARotProvisioning:
		return "cca-platform-rot-provisioning"
	case StateSecured:
		return "secured"
	case StateNonCCAPlatformDebug:
		return "non-cca-platform-rot-debug"
	case StateRecoverableCCAPlatformDebug:
		return "recoverable-cca-platform-rot-debug"
	case StateDecommissioned:
		return "decommissioned"
	default:
		return "invalid"
	}
}

// LifeCycleToState translates the provide life cycle claim value into
// corresponding LifeCycleState.If the value is not within valid range, then
// StateInvalid is returned.
func LifeCycleToState(v uint16) LifeCycleState {
	if v >= LifecycleUnknownMin &&
		v <= LifecycleUnknownMax {
		return StateUnknown
	}

	if v >= LifecycleAssemblyAndTestMin &&
		v <= LifecycleAssemblyAndTestMax {
		return StateAssemblyAndTest
	}

	if v >= LifecycleRotProvisioningMin &&
		v <= LifecycleRotProvisioningMax {
		return StateCCARotProvisioning
	}

	if v >= LifecycleSecuredMin &&
		v <= LifecycleSecuredMax {
		return StateSecured
	}

	if v >= LifecycleNonCCAPlatformDebugMin &&
		v <= LifecycleNonCCAPlatformDebugMax {
		return StateNonCCAPlatformDebug
	}

	if v >= LifecycleRecoverableCCAPlatformDebugMin &&
		v <= LifecycleRecoverableCCAPlatformDebugMax {
		return StateRecoverableCCAPlatformDebug
	}

	if v >= LifecycleDecommissionedMin &&
		v <= LifecycleDecommissionedMax {
		return StateDecommissioned
	}

	return StateInvalid
}

// ValidateSecurityLifeCycle returns an error if the provided value does not
// correspond to a valid LifeCycleState.
func ValidateSecurityLifeCycle(v uint16) error {
	if !LifeCycleToState(v).IsValid() {
		return fmt.Errorf("%w: value %d is invalid", psatoken.ErrWrongSyntax, v)
	}

	return nil
}
