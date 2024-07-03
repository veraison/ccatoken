// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package realm

import "github.com/veraison/ccatoken/encoding"

var (
	em, emError = encoding.InitCBOREncMode()
	dm, dmError = encoding.InitCBORDecMode()
)

func init() {
	if emError != nil {
		panic(emError)
	}
	if dmError != nil {
		panic(dmError)
	}
}
