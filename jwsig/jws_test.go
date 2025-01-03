// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package jwsig

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestJwsMarshaling(t *testing.T) {
	payloadJson := []byte(`{"a": "1", "b": 2}`)
	// payloadB64 := string(util.Base64EncodeForJWT(tc.payload))

	testCases := []struct {
		name          string
		payload       []byte
		tokens        []string
		publicHeaders []map[string]any
		expectedJson  string
	}{
		{name: "with only payload",
			payload:       payloadJson,
			expectedJson:  `{"payload":"eyJhIjogIjEiLCAiYiI6IDJ9","signatures":[]}`,
			publicHeaders: []map[string]any{},
		},
		{name: "with one token",
			payload: payloadJson,
			tokens: []string{
				"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJhIjogIjEiLCAiYiI6IDJ9.ZmFrZXNpZ25hdHVyZQ=="},
			expectedJson:  `{"payload":"eyJhIjogIjEiLCAiYiI6IDJ9","signatures":[{"protected":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ","signature":"ZmFrZXNpZ25hdHVyZQ=="}]}`,
			publicHeaders: []map[string]any{},
		},
		{name: "with two tokens",
			payload: payloadJson,
			tokens: []string{
				"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJhIjogIjEiLCAiYiI6IDJ9.ZmFrZXNpZ25hdHVyZQ==",
				"eyJhbGciOiJSUzI1NiIsInR5cCI6IkNJQyIsImtpZCI6IjEyMzQifQ.eyJhIjogIjEiLCAiYiI6IDJ9.YW5vdGhlcmZha2VzaWc="},
			publicHeaders: []map[string]any{},
			expectedJson:  `{"payload":"eyJhIjogIjEiLCAiYiI6IDJ9","signatures":[{"protected":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ","signature":"ZmFrZXNpZ25hdHVyZQ=="},{"protected":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkNJQyIsImtpZCI6IjEyMzQifQ","signature":"YW5vdGhlcmZha2VzaWc="}]}`,
		},
		{name: "with three tokens and public header",
			payload: payloadJson,
			tokens: []string{
				"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJhIjogIjEiLCAiYiI6IDJ9.ZmFrZXNpZ25hdHVyZQ==",
				"eyJhbGciOiJSUzI1NiIsInR5cCI6IkNJQyIsImtpZCI6IjEyMzQifQ.eyJhIjogIjEiLCAiYiI6IDJ9.YW5vdGhlcmZha2VzaWc=",
				"eyJhbGciOiJSUzI1NiIsInR5cCI6IkNPUyIsImtpZCI6IjEyMzQifQ.eyJhIjogIjEiLCAiYiI6IDJ9.ZXh0cmFmYWtlc2ln"},
			publicHeaders: []map[string]any{{"a": "1", "b": 2}, nil, nil},
			expectedJson:  `{"payload":"eyJhIjogIjEiLCAiYiI6IDJ9","signatures":[{"protected":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ","header":{"a":"1","b":2},"signature":"ZmFrZXNpZ25hdHVyZQ=="},{"protected":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkNJQyIsImtpZCI6IjEyMzQifQ","signature":"YW5vdGhlcmZha2VzaWc="},{"protected":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkNPUyIsImtpZCI6IjEyMzQifQ","signature":"ZXh0cmFmYWtlc2ln"}]}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwsObj := Jws{
				Payload:    string(util.Base64EncodeForJWT(tc.payload)),
				Signatures: []Signature{},
			}

			for i, v := range tc.tokens {
				token := []byte(v)
				if i < len(tc.publicHeaders) {
					public := tc.publicHeaders[i]
					err := jwsObj.AddSignature(token, WithPublicHeader(public))
					require.NoError(t, err)
				} else {
					err := jwsObj.AddSignature(token)
					require.NoError(t, err)
				}
			}
			if len(tc.tokens) > 0 {
				token, err := jwsObj.GetTokenByTyp("JWT")
				require.NoError(t, err)
				require.NotNil(t, token)

				token, err = jwsObj.GetToken(0)
				require.NoError(t, err)
				require.NotNil(t, token)
			}

			jwsJson, err := json.Marshal(jwsObj)
			require.NoError(t, err)
			require.NotNil(t, jwsJson)

			fmt.Println(string(jwsJson))
			require.Equal(t, tc.expectedJson, string(jwsJson), "marshalled json doesn't match expected json")

			var jwsObjUnmarshalled Jws
			err = json.Unmarshal(jwsJson, &jwsObjUnmarshalled)
			require.NoError(t, err)
			JwsEqual(t, jwsObj, jwsObjUnmarshalled)

		})
	}
}

func JwsEqual(t *testing.T, j1 Jws, j2 Jws) {
	require.Equal(t, j1.Payload, j2.Payload, "payloads don't match")
	require.Equal(t, len(j1.Signatures), len(j1.Signatures))
}
