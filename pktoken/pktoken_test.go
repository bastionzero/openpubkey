// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package pktoken_test

import (
	"bytes"
	"crypto"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"

	"github.com/openpubkey/openpubkey/jwsig"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
)

func TestPkToken(t *testing.T) {
	alg := jwa.ES256

	signingKey, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	pkt, err := mocks.GenerateMockPKToken(t, signingKey, alg)
	require.NoError(t, err)

	testPkTokenMessageSigning(t, pkt, signingKey)
	testPkTokenSerialization(t, pkt)

	actualIssuer, err := pkt.Issuer()
	require.NoError(t, err)
	require.Equal(t, "mockIssuer", actualIssuer)

	actualAlg, ok := pkt.ProviderAlgorithm()
	require.True(t, ok)
	require.Equal(t, "RS256", actualAlg.String())

}

func testPkTokenMessageSigning(t *testing.T, pkt *pktoken.PKToken, signingKey crypto.Signer) {
	// Create new OpenPubKey Signed Message (OSM)
	msg := "test message!"
	osm, err := pkt.NewSignedMessage([]byte(msg), signingKey)
	require.NoError(t, err)

	// Verify our OSM is valid
	payload, err := pkt.VerifySignedMessage(osm)
	require.NoError(t, err)

	require.Equal(t, msg, string(payload), "OSM payload did not match what we initially wrapped")
}

func testPkTokenSerialization(t *testing.T, pkt *pktoken.PKToken) {
	// Test json serialization/deserialization
	pktJson, err := json.Marshal(pkt)
	require.NoError(t, err)

	var newPkt *pktoken.PKToken
	err = json.Unmarshal(pktJson, &newPkt)
	require.NoError(t, err)

	newPktJson, err := json.Marshal(newPkt)
	require.NoError(t, err)

	require.JSONEq(t, string(pktJson), string(newPktJson))

	// Simple Compact sanity test
	pktCom, err := pkt.Compact()
	require.NoError(t, err)
	require.NotNil(t, pktCom)

	pktFromCom, err := pktoken.NewFromCompact(pktCom)
	require.NoError(t, err)
	require.NotNil(t, pktFromCom.OpToken)
	require.NotNil(t, pktFromCom.CicToken)
}

// This test builds a PK Token from a set of test vectors and then checks
// that our serialization code preserves the exact values supplied as
// test vectors. This is input because even minor whitespace or ordering
// changes can break signature verification.
func TestPkTokenJwsUnchanged(t *testing.T) {
	payload := `{
		"aud": "testAud",
		"email": "arthur.aardvark@example.com",
		"exp": 1708641372,
		"iat": 1708554972,
		"iss": "mockIssuer",
		"nonce": "iOqVQfpJsbt4gpcGUX0lJLT82bTm8PU1fwNghiGau0M",
		"sub": "1234567890"
	  }`

	testCases := []struct {
		name         string
		payload      string
		opProtected  string
		cicProtected string
		cosProtected string
	}{
		{name: "with alphabetical order",
			payload:      payload,
			opProtected:  `{"alg":"RS256","typ":"JWT"}`,
			cicProtected: `{"alg":"ES256","rz":"872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e","typ":"CIC","upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}`,
			cosProtected: `{"alg":"ES256","auth_time":1708991378,"eid":"1234","exp":1708994978,"iat":1708991378,"iss":"example.com","kid":"1234","nonce":"test-nonce","ruri":"http://localhost:3000","typ":"COS"}`,
		},
		{name: "with reverse alphabetical order",
			payload:      payload,
			opProtected:  `{"typ":"JWT","alg":"RS256"}`,
			cicProtected: `{"upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}, "typ":"CIC", "rz":"872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e", "alg":"ES256"}`,
			cosProtected: `{"typ":"COS","ruri":"http://localhost:3000","nonce":"test-nonce","kid":"1234","iss":"example.com","iat":1708991378,"exp":1708994978,"eid":"none","auth_time":1708991378,"alg":"ES256"}`,
		},
		{name: "with extra whitespace",
			payload:      payload,
			opProtected:  `{  "alg" : "RS256",     "typ": "JWT" }`,
			cicProtected: `{  "alg" : "ES256",  "rz": "872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e" , "typ":"CIC","upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}`,
			cosProtected: `{  "alg" : "ES256",  "auth_time": 1708991378,"eid":"1234","exp":1708994978,"iat":1708991378,"iss":"example.com","kid":"1234","nonce":"test-nonce","ruri":"http://localhost:3000","typ":"COS"}`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testUnchanged(t, tc.payload, tc.opProtected, tc.cicProtected, tc.cosProtected)
		})
	}
}

func testUnchanged(t *testing.T, payload string, opPheader string, cicPheader string, cosPheader string) {
	pkt := &pktoken.PKToken{}

	// Build OP Token and add it to PK Token
	opTokenOriginal := BuildToken(opPheader, payload, "fakeSignature OP")
	err := pkt.AddSignature(opTokenOriginal, pktoken.OIDC)
	require.NoError(t, err)

	// Build CIC Token and add it to PK Token
	cicTokenOriginal := BuildToken(cicPheader, payload, "fakeSignature")
	err = pkt.AddSignature(cicTokenOriginal, pktoken.CIC)
	require.NoError(t, err)

	// Build CIC Token and add it to PK Token
	cosTokenOriginal := BuildToken(cosPheader, payload, "fakeSignature")
	err = pkt.AddSignature(cosTokenOriginal, pktoken.COS)
	require.NoError(t, err)

	// Check that Marshal PK Token to Json leaves underlying signed values unchanged
	pktJson, err := pkt.MarshalJSON()
	require.NoError(t, err)

	// Unmarshal it into a simple JWS structure to see if the underlying values have changed
	var simpleJWS jwsig.Jws
	err = json.Unmarshal(pktJson, &simpleJWS)
	require.NoError(t, err)

	opTokenUnmarshalled, err := simpleJWS.GetTokenByTyp("JWT") // JWT is the token typ used by the OP Token (ID Token)
	require.NoError(t, err)
	require.EqualValues(t, string(opTokenOriginal), string(opTokenUnmarshalled), "danger, signed values in OP Token being changed during marshalling")

	cicTokenUnmarshalled, err := simpleJWS.GetTokenByTyp("CIC") // CIC is the token typ used by the OP Token (ID Token)
	require.NoError(t, err)
	require.EqualValues(t, string(cicTokenOriginal), string(cicTokenUnmarshalled), "danger, signed values in CIC Token being changed during marshalling")

	cosTokenUnmarshalled, err := simpleJWS.GetTokenByTyp("COS") // COS is the token typ used by the OP Token (ID Token)
	require.NoError(t, err)
	require.EqualValues(t, string(cosTokenOriginal), string(cosTokenUnmarshalled), "danger, signed values in CIC Token being changed during marshalling")

	// Check that ToCompact and FromCompact leaves underlying signed values unchanged
	pktCom, err := pkt.Compact()
	require.NoError(t, err)
	pktFromCom, err := pktoken.NewFromCompact(pktCom)
	require.NoError(t, err)

	require.EqualValues(t, string(opTokenOriginal), string(pktFromCom.OpToken), "danger, signed values in OP Token being changed after compact")
	require.EqualValues(t, string(cicTokenOriginal), string(pktFromCom.CicToken), "danger, signed values in CIC Token being changed after compact")
	require.EqualValues(t, string(cosTokenOriginal), string(pktFromCom.CosToken), "danger, signed values in COS Token being changed after compact")
}

// This test builds a PK Token from a set of test vectors and then checks
// that the ToCompact constructs the PK Token correctly and that FromCompact
// reconstructs the PK Token correctly.
func TestCompact(t *testing.T) {
	payload := `{
		"aud": "testAud",
		"email": "arthur.aardvark@example.com",
		"exp": 1708641372,
		"iat": 1708554972,
		"iss": "mockIssuer",
		"nonce": "iOqVQfpJsbt4gpcGUX0lJLT82bTm8PU1fwNghiGau0M",
		"sub": "1234567890"
	  }`

	testCases := []struct {
		name                string
		payload             string
		opProtected         string
		cicProtected        string
		cosProtected        string
		expToCompactError   string
		expFromCompactError string
	}{
		{name: "Happy case with OP, CIC tokens",
			payload:      payload,
			opProtected:  `{"alg":"RS256","typ":"JWT"}`,
			cicProtected: `{"alg":"ES256","rz":"872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e","typ":"CIC","upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}`,
		},
		{name: "Happy case with OP, CIC and COS tokens",
			payload:      payload,
			opProtected:  `{"alg":"RS256","typ":"JWT"}`,
			cicProtected: `{"alg":"ES256","rz":"872c6399f440d80a8c28935d8dd84da13ecdfc8e99b3dfbf92bdf1a3133a0b5e","typ":"CIC","upk":{"alg":"ES256","crv":"P-256","kty":"EC","x":"1UxCtDCjyb0bSz9P815sMTqGjSdF2u-sYk0egy4yigs","y":"0qQnHkOLMyQY5WwnpjaFO2TzGCtq_nFg10fI16LcexE"}}`,
			cosProtected: `{"alg":"ES256","auth_time":1708991378,"eid":"1234","exp":1708994978,"iat":1708991378,"iss":"example.com","kid":"1234","nonce":"test-nonce","ruri":"http://localhost:3000","typ":"COS"}`,
		},
		{name: "No Tokens",
			expToCompactError: "no tokens provided",
			payload:           payload,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := &pktoken.PKToken{}

			tokensAdded := 0
			// Let's us test the case with no CIC Token.
			if tc.opProtected != "" {
				// Build OP Token and add it to PK Token
				opTokenOriginal := BuildToken(tc.opProtected, tc.payload, "fakeSignature OP")
				err := pkt.AddSignature(opTokenOriginal, pktoken.OIDC)
				require.NoError(t, err)
				tokensAdded += 1
			}

			// Let's us test the case with no CIC Token.
			if tc.cicProtected != "" {
				// Build CIC Token and add it to PK Token
				cicTokenOriginal := BuildToken(tc.cicProtected, payload, "fakeSignature")
				err := pkt.AddSignature(cicTokenOriginal, pktoken.CIC)
				require.NoError(t, err)
				tokensAdded += 1
			}

			// Let's us test the case with no COS Token. This is not an error case.
			if tc.cosProtected != "" {
				// Build CIC Token and add it to PK Token
				cosTokenOriginal := BuildToken(tc.cosProtected, payload, "fakeSignature")
				err := pkt.AddSignature(cosTokenOriginal, pktoken.COS)
				require.NoError(t, err)
				tokensAdded += 1
			}

			pktCom, err := pkt.Compact()
			if tc.expToCompactError != "" {
				require.ErrorContains(t, err, tc.expToCompactError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, pktCom)
				parts := bytes.Split(pktCom, []byte(":"))
				expParts := tokensAdded*2 + 1
				require.Equal(t, expParts, len(parts), "number of expected parts in compact (%d) does not match number of parts found (%d) ", expParts, len(parts))

				// Try build a PK Token from the compact representation
				pktFromCom, err := pktoken.NewFromCompact(pktCom)
				if tc.expFromCompactError != "" {
					require.ErrorContains(t, err, tc.expFromCompactError)
				} else {
					require.NoError(t, err)
					require.NotNil(t, pktFromCom)

					require.Equal(t, pkt.OpToken, pktFromCom.OpToken)
					require.Equal(t, pkt.Op, pktFromCom.Op)

					require.Equal(t, pkt.CicToken, pktFromCom.CicToken)
					require.Equal(t, pkt.Cic, pktFromCom.Cic)

					require.Equal(t, pkt.CosToken, pktFromCom.CosToken)
					require.Equal(t, pkt.Cos, pktFromCom.Cos)

					actualIssuer, err := pktFromCom.Issuer()
					require.NoError(t, err)
					require.Equal(t, "mockIssuer", actualIssuer)
				}

				// Test Deep Copy
				pktCopy1, err := pkt.DeepCopy()
				require.NoError(t, err)
				pktCopy2, err := pkt.DeepCopy()
				require.NoError(t, err)
				require.Equal(t, pktCopy1.OpToken, pktCopy2.OpToken)
				require.Equal(t, pktCopy1.Op, pktCopy2.Op)
				require.Equal(t, pktCopy1.FreshIDToken, pktCopy2.FreshIDToken)

				pktCopy1.OpToken = []byte("Overwritten-OP-Token")
				pktCopy1.Op.SetSignature([]byte{0x0})
				pktCopy1.FreshIDToken = []byte("Overwritten-Fresh-ID-Token")

				require.NotEqual(t, pktCopy1.OpToken, pktCopy2.OpToken)
				require.NotEqual(t, pktCopy1.Op, pktCopy2.Op)
				require.NotEqual(t, pktCopy1.FreshIDToken, pktCopy2.FreshIDToken)
			}

		})
	}
}

//go:embed test_jwk.json
var test_jwk []byte

// based on https://www.rfc-editor.org/rfc/rfc7638.html
func TestThumprintCalculation(t *testing.T) {
	fromRfc := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	pub, err := jwk.ParseKey(test_jwk)
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	thumbEnc := util.Base64EncodeForJWT(thumb)
	if string(thumbEnc) != fromRfc {
		t.Fatalf("thumbprint %s did not match expected value %s", thumbEnc, fromRfc)
	}

}

func BuildToken(protected string, payload string, sig string) []byte {
	return util.JoinJWTSegments(
		util.Base64EncodeForJWT([]byte(protected)),
		util.Base64EncodeForJWT([]byte(payload)),
		util.Base64EncodeForJWT([]byte(sig)))
}
