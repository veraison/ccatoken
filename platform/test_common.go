// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"encoding/hex"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/veraison/psatoken"
)

var (
	testNotJSON          = []byte(`{`)
	testNotCBOR          = `6e6f745f63626f720a`
	testConfig           = []byte{1, 2, 3}
	testHashAlgID        = "sha-256"
	testImplementationID = []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	testNonce = []byte{
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
	}
	testInstID = []byte{
		0x01, // RAND
		2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2,
	}
	testVSI              = "https://veraison.example/v1/challenge-response"
	testMeasurementValue = []byte{
		3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3,
	}
	testSignerID = []byte{
		4, 4, 4, 4, 4, 4, 4, 4,
		4, 4, 4, 4, 4, 4, 4, 4,
		4, 4, 4, 4, 4, 4, 4, 4,
		4, 4, 4, 4, 4, 4, 4, 4,
	}
	testSoftwareComponents = []psatoken.ISwComponent{
		&psatoken.SwComponent{
			MeasurementValue: &testMeasurementValue,
			SignerID:         &testSignerID,
		},
	}
)

func mustHexDecode(t *testing.T, s string) []byte {
	// support CBOR-diag "pretty" format:
	// * allow long hex string to be split over multiple lines (with soft or
	//   hard tab indentation)
	// * allow comments starting with '#' up to the NL
	comments := regexp.MustCompile("#.*\n")
	emptiness := regexp.MustCompile("[ \t\n]")

	s = comments.ReplaceAllString(s, "")
	s = emptiness.ReplaceAllString(s, "")

	data, err := hex.DecodeString(s)
	if t != nil {
		require.NoError(t, err)
	} else if err != nil {
		panic(err)
	}
	return data
}
