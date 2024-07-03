// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_DecodeClaims(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaPlatformClaimsAll)
	_, err := DecodeClaims(buf)
	assert.NoError(t, err)

	buf = mustHexDecode(t, testEncodedCcaPlatformClaimsInvalidMultiNonce)
	_, err = DecodeClaims(buf)
	assert.EqualError(t, err, "validation of CCA platform claims failed: validating nonce: wrong syntax: got 2 nonces, want 1")
}
