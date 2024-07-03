// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ccatoken

import "github.com/veraison/ccatoken/encoding"

var (
	tags = []encoding.CBORTagEntry{
		{Type: CBORCollection{}, Tag: 399},
	}
	em, emError = encoding.InitCBOREncMode(tags...)
	dm, dmError = encoding.InitCBORDecMode(tags...)
)

func init() {
	if emError != nil {
		panic(emError)
	}
	if dmError != nil {
		panic(dmError)
	}
}
