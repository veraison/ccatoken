package ccatoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"reflect"
	"regexp"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/require"
	cose "github.com/veraison/go-cose"
	"github.com/veraison/psatoken"
)

var (
	testNotJSON            = []byte(`{`)
	testNotCBOR            = `6e6f745f63626f720a`
	testChallenge          = []byte("ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB")
	testPersonalizationVal = []byte("ADADADADADADADADADADADADADADADADADADADADADADADADADADADADADADADAD")
	testInitMeas           = []byte("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	testPEMKey             = []byte("-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAUpTBCqGYMwJ/qywlXHrHwZec2dLYE9xNYjtR6BEjLEC1NYJMDlUfk\ngCQORURs0zigBwYFK4EEACKhZANiAASBGViAoiB/uVYDKjy5f12lr3Jv/LcV7hZH\nhKf7FsBglr3ZRioyZQspEqhVFXDW6h87LR99qKJ1+gAzDwB4YYvD4UlUnIFw0y7F\nWJCn+ex4nx8YrpLrFdIir5cdlxyWWvE=\n-----END EC PRIVATE KEY-----")
	testExtensibleMeas     = [][]byte{
		testInitMeas,
		testInitMeas,
		testInitMeas,
		testInitMeas,
	}
	testHashAlgID       = "sha-256"
	testPubKey          = []byte("YBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBYBY")
	testPubKeyHashAlgID = "sha-512"
	testECKeyA          = `{
	  "kty": "EC",
	  "crv": "P-256",
	  "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	  "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	  "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
	}`

	testECKeyB = `{
		"kty": "EC",
		"crv": "P-256",
		"x": "eeupDov0UKZ1FXatRZmwet-TjaO7C9F9ADbtSaLQ_D8",
		"y": "v836iVa1aL_bhnPmSNi1jZKZVbFKJsMIDzQRfZcdaGQ",
		"d": "qbRUsm1vkKTqMRk1ZMupH-xvmgAqfcBQS5Khk3E0WF8"
	   }`

	testECKeyC = `{
		"kty": "EC",
		"crv": "P-256",
		"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqx7D4",
		"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
	  }`
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

func signerFromJwKey(t *testing.T, jkey jwk.Key) cose.Signer {
	var (
		key crypto.Signer
		crv elliptic.Curve
		alg cose.Algorithm
	)
	err := jkey.Raw(&key)
	require.NoError(t, err)
	switch v := key.(type) {
	case *ecdsa.PrivateKey:
		crv = v.Curve
		if crv == elliptic.P256() {
			alg = cose.AlgorithmES256
			break
		} else if crv == elliptic.P384() {
			alg = cose.AlgorithmES384
			break
		}
		require.True(t, false, "unknown elliptic curve %v", crv)
	default:
		require.True(t, false, "unknown private key type %v", reflect.TypeOf(key))
	}
	s, err := cose.NewSigner(alg, key)
	require.Nil(t, err)

	return s
}

func pubKeyFromJwKey(t *testing.T, jkey jwk.Key) crypto.PublicKey {
	var key crypto.Signer
	err := jkey.Raw(&key)
	require.NoError(t, err)
	vk := key.Public()
	return vk
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
		crv = v.Curve
		if crv == elliptic.P256() {
			alg = cose.AlgorithmES256
			break
		}
		require.True(t, false, "unknown elliptic curve %v", crv)
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

func getJwkKeyFromPemKey(testKey []byte) (jwk.Key, error) {
	key, err := jwk.ParseKey(testKey, jwk.WithPEM(true))
	if err != nil {
		return nil, err
	}
	fmt.Printf("received key = %s", key)
	return key, nil
}
