// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// This file defines a profile registry for realm claims, similar to https://github.com/veraison/psatoken/blob/main/profile.go
// Unlike platform.IClaims, realm.IClaims cannot reuse psatoken's profile registry because it does not extend psatoken.IClaims.
// Therefore, a realm.IClaims profile registry is defined here, with the aim of easing the addition of future profiles.

package realm

import (
	"fmt"

	"github.com/veraison/psatoken/encoding"
)

// IProfile defines a way of obtaining an implementation of IClaims that
// corresponds to a particular profile of a CCA Realm state token.
type IProfile interface {
	// GetName returns the name of this profile.
	GetName() string
	// GetClaims returns a new instance of the IClaims implementation
	// associated with this profile, with the Profile field set to the profile name.
	GetClaims() IClaims
	// GetUninitializedClaims returns an empty instance of the IClaims implementation
	// associated with this profile, with all fields unset. Used for decoding.
	GetUninitializedClaims() IClaims
}

// RegisterProfile adds the provided IProfile implementation to the global
// register which is used by DecodeClaimsFromCBOR and DecodeClaimsFromJSON.
// An error is returned if a profile with an identical name is already
// registered.
func RegisterProfile(p IProfile) error {
	return registerProfileUnderName(p.GetName(), p)
}

type profileEntry struct {
	Profile IProfile
	JSONTag string
}

var profilesRegister = map[string]profileEntry{}

func registerDefaultProfile(p IProfile) error {
	return registerProfileUnderName("", p)
}

func registerProfileUnderName(name string, profile IProfile) error {
	if _, ok := profilesRegister[name]; ok {
		return fmt.Errorf("profile %q already registered", name)
	}

	tag, err := encoding.GetProfileJSONTag(profile.GetClaims())
	if err != nil {
		return fmt.Errorf("could not identify JSON tag for Profile field: %w", err)
	}

	profilesRegister[name] = profileEntry{Profile: profile, JSONTag: tag}

	return nil
}
