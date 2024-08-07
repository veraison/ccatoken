package realm

import (
	"encoding/hex"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testNotJSON            = []byte(`{`)
	testNotCBOR            = `6e6f745f63626f720a`
	testChallenge          = []byte("ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB")
	testPersonalizationVal = []byte("ADADADADADADADADADADADADADADADADADADADADADADADADADADADADADADADAD")
	testInitMeas           = []byte("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	testExtensibleMeas     = [][]byte{
		testInitMeas,
		testInitMeas,
		testInitMeas,
		testInitMeas,
	}
	testHashAlgID       = "sha-256"
	testPubKeyHashAlgID = "sha-512"

	testRAKPubRaw = []byte{
		0x04, 0x81, 0x19, 0x58, 0x80, 0xa2, 0x20, 0x7f, 0xb9, 0x56, 0x03, 0x2a,
		0x3c, 0xb9, 0x7f, 0x5d, 0xa5, 0xaf, 0x72, 0x6f, 0xfc, 0xb7, 0x15, 0xee,
		0x16, 0x47, 0x84, 0xa7, 0xfb, 0x16, 0xc0, 0x60, 0x96, 0xbd, 0xd9, 0x46,
		0x2a, 0x32, 0x65, 0x0b, 0x29, 0x12, 0xa8, 0x55, 0x15, 0x70, 0xd6, 0xea,
		0x1f, 0x3b, 0x2d, 0x1f, 0x7d, 0xa8, 0xa2, 0x75, 0xfa, 0x00, 0x33, 0x0f,
		0x00, 0x78, 0x61, 0x8b, 0xc3, 0xe1, 0x49, 0x54, 0x9c, 0x81, 0x70, 0xd3,
		0x2e, 0xc5, 0x58, 0x90, 0xa7, 0xf9, 0xec, 0x78, 0x9f, 0x1f, 0x18, 0xae,
		0x92, 0xeb, 0x15, 0xd2, 0x22, 0xaf, 0x97, 0x1d, 0x97, 0x1c, 0x96, 0x5a,
		0xf1,
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
