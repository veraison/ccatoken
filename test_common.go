package ccatoken

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
	testPubKey          = []byte("YBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBY")
	testPubKeyHashAlgID = "sha-512"
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
