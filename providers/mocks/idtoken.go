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

package mocks

import (
	"crypto"
	"encoding/json"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/openpubkey/openpubkey/jwsig"
)

type CommitmentType struct {
	ClaimCommitment bool
	ClaimName       string
}

type IDTokenTemplate struct {
	CommitFunc           func(*IDTokenTemplate, string)
	Issuer               string
	Nonce                string
	NoNonce              bool
	Aud                  string
	KeyID                string
	NoKeyID              bool
	Alg                  string
	NoAlg                bool // Even if NOAlg is true, we still need Alg to be set to generate the signature
	ExtraClaims          map[string]any
	ExtraProtectedClaims map[string]any
	SigningKey           crypto.Signer // The key we will use to sign the ID Token
}

func DefaultIDTokenTemplate() IDTokenTemplate {
	return IDTokenTemplate{
		CommitFunc: AddAudCommit,
		Issuer:     "mockIssuer",
		Nonce:      "empty",
		NoNonce:    false,
		Aud:        "empty",
		KeyID:      "mockKeyID",
		NoKeyID:    false,
		Alg:        "RS256",
		NoAlg:      false,
	}
}

// AddCommit adds the commitment to the CIC to the ID Token. The
// CommitmentFunc is specified allowing custom commitment functions to be specified
func (t *IDTokenTemplate) AddCommit(cicHash string) {
	t.CommitFunc(t, cicHash)
}

// TODO: Rename to IssueTokens
func (t *IDTokenTemplate) IssueToken() (*jwsig.Tokens, error) {

	headers := jws.NewHeaders()
	if !t.NoAlg {
		if err := headers.Set(jws.AlgorithmKey, t.Alg); err != nil {
			return nil, err
		}
	}
	if !t.NoKeyID {
		if err := headers.Set(jws.KeyIDKey, t.KeyID); err != nil {
			return nil, err
		}
	}
	if err := headers.Set(jws.TypeKey, "JWT"); err != nil {
		return nil, err
	}

	if t.ExtraProtectedClaims != nil {
		for k, v := range t.ExtraProtectedClaims {
			if err := headers.Set(k, v); err != nil {
				return nil, err
			}
		}
	}

	payloadMap := map[string]any{
		"sub": "me",
		"aud": t.Aud,
		"iss": t.Issuer,
		"iat": time.Now().Unix(),
	}

	if !t.NoNonce {
		payloadMap["nonce"] = t.Nonce
	}

	if t.ExtraClaims != nil {
		for k, v := range t.ExtraClaims {
			payloadMap[k] = v
		}
	}

	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, err
	}

	idToken, err := jws.Sign(
		payloadBytes,
		jws.WithKey(
			jwa.KeyAlgorithmFrom(t.Alg),
			t.SigningKey,
			jws.WithProtectedHeaders(headers),
		),
	)
	if err != nil {
		return nil, err
	}
	return &jwsig.Tokens{
		IDToken:      idToken,
		RefreshToken: []byte("mock-refresh-token"),
		AccessToken:  []byte("mock-access-token")}, nil
}

func AddNonceCommit(idtTemp *IDTokenTemplate, cicHash string) {
	idtTemp.Nonce = cicHash
	idtTemp.NoNonce = false
}

func AddAudCommit(idtTemp *IDTokenTemplate, cicHash string) {
	idtTemp.Aud = cicHash
}

func NoClaimCommit(idtTemp *IDTokenTemplate, cicHash string) {
	// Do nothing
}
