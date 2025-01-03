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

package providers

import (
	"context"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/jwsig"
	"github.com/openpubkey/openpubkey/util"
)

func TestGQ(t *testing.T) {

	testCases := []struct {
		name            string
		tokenCommitType CommitType
		gqCommitment    bool
		cicHash         string
		wrongAlg        bool
		wrongKid        bool
		expError        string
	}{
		{name: "happy case (nonce commit)",
			tokenCommitType: CommitTypesEnum.NONCE_CLAIM,
		},
		{name: "happy case (GQ bound)",
			tokenCommitType: CommitTypesEnum.GQ_BOUND,
			gqCommitment:    true,
			cicHash:         "fake-cic-hash",
		},
		{name: "change alg to ES256, should fail",
			tokenCommitType: CommitTypesEnum.GQ_BOUND,
			wrongAlg:        true,
			expError:        "gq signatures require ID Token have signed with an RSA key, ID Token alg was (EC256)",
		},
		{name: "ID Token has kid that exist in OP's JWKS",
			tokenCommitType: CommitTypesEnum.GQ_BOUND,
			wrongKid:        true,
			expError:        "no matching public key found for kid wrong-kid",
		},
		{name: "cicHash set but not GQ bound",
			tokenCommitType: CommitTypesEnum.GQ_BOUND,
			gqCommitment:    false,
			cicHash:         "fake-cic-hash",
			expError:        "misconfiguration, cicHash is set but gqCommitment is false",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			providerOpts := DefaultMockProviderOpts()
			providerOpts.NumKeys = 1 // Only use 1 public key so we can find the public key used
			providerOpts.CommitType = tc.tokenCommitType

			op, backend, idtTemplate, err := NewMockProvider(providerOpts)
			require.NoError(t, err)

			expPublicKey := maps.Values(backend.GetProviderPublicKeySet())[0].PublicKey

			tokens, err := idtTemplate.IssueToken()
			require.NoError(t, err)
			idToken := tokens.IDToken

			if tc.wrongAlg {
				protected := util.Base64EncodeForJWT([]byte(`{"alg": "EC256","kid": "kid-0","typ": "JWT"}`))
				idToken = []byte(string(protected) + ".e30.ZmFrZXNpZw")
			}

			if tc.wrongKid {
				protected := util.Base64EncodeForJWT([]byte(`{"alg": "RS256","kid": "wrong-kid","typ": "JWT"}`))
				idToken = []byte(string(protected) + ".e30.ZmFrZXNpZw")
			}

			gqToken, err := createGQTokenAllParams(context.Background(), idToken, op, tc.cicHash, tc.gqCommitment)

			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, gqToken)

				// Check that GQ Signature verifies
				verifies, err := gq.GQ256VerifyJWT(expPublicKey.(*rsa.PublicKey), gqToken)
				require.NoError(t, err)
				require.True(t, verifies)

				jwt, err := jwsig.NewJwt(gqToken)
				require.NoError(t, err)
				typ, err := jwt.GetSignature().GetTyp()
				require.NoError(t, err)
				require.Equal(t, "JWT", typ)
				jktFound := jwt.GetSignature().GetProtectedClaims().Jkt
				require.NotEmpty(t, jktFound)

				expJkt, err := createJkt(expPublicKey)
				require.NoError(t, err)
				require.Equal(t, expJkt, jktFound, "JKT in GQ ID Token does not match expected JKT")
			}
		})
	}
}
