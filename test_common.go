package ccatoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"reflect"
	"regexp"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/require"
	cose "github.com/veraison/go-cose"
	"github.com/veraison/psatoken"
)

var (
	testRAK = `{
		"crv": "P-384",
		"d": "FKUwQqhmDMCf6ssJVx6x8GXnNnS2BPcTWI7UegRIyxAtTWCTA5VH5IAkDkVEbNM4",
		"kty": "EC",
		"x": "gRlYgKIgf7lWAyo8uX9dpa9yb_y3Fe4WR4Sn-xbAYJa92UYqMmULKRKoVRVw1uof",
		"y": "Oy0ffaiidfoAMw8AeGGLw-FJVJyBcNMuxViQp_nseJ8fGK6S6xXSIq-XHZccllrx"
	  }`

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
	testIAK = `{
	  "kty": "EC",
	  "crv": "P-256",
	  "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	  "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	  "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
	}`
	testAltIAK = `{
		"kty": "EC",
		"crv": "P-256",
		"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqx7D4",
		"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
	  }`
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

	testPlatformLifecycleSecured = uint16(psatoken.CcaPlatformLifecycleSecuredMin)
	testConfig                   = []byte{1, 2, 3}
	testImplementationID         = []byte{
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
	testSoftwareComponents = []psatoken.SwComponent{
		{
			MeasurementValue: &testMeasurementValue,
			SignerID:         &testSignerID,
		},
	}
	testCcaProfile = "http://arm.com/CCA-SSD/1.0.0"
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

func signerFromJWK(t *testing.T, j string) cose.Signer {
	alg, key := getAlgAndKeyFromJWK(t, j)
	s, err := cose.NewSigner(alg, key)
	require.Nil(t, err)

	return s
}

func getAlgAndKeyFromJWK(t *testing.T, j string) (cose.Algorithm, crypto.Signer) {
	ks, err := jwk.ParseString(j)
	require.Nil(t, err)

	var (
		key crypto.Signer
		crv elliptic.Curve
		alg cose.Algorithm
	)

	k, ok := ks.Get(0)
	require.True(t, ok)
	err = k.Raw(&key)
	require.NoError(t, err)

	switch v := key.(type) {
	case *ecdsa.PrivateKey:
		switch v.Curve {
		case elliptic.P256():
			alg = cose.AlgorithmES256
		case elliptic.P384():
			alg = cose.AlgorithmES384
		default:
			require.True(t, false, "unknown elliptic curve %v", crv)
		}
	default:
		require.True(t, false, "unknown private key type %v", reflect.TypeOf(key))
	}
	return alg, key
}

func pubKeyFromJWK(t *testing.T, j string) crypto.PublicKey {
	_, key := getAlgAndKeyFromJWK(t, j)
	vk := key.Public()
	return vk
}
