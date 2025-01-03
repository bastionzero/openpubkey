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

package providers

import (
	"context"
	"fmt"

	"github.com/awnumar/memguard"
	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/jwsig"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

const gitlabIssuer = "https://gitlab.com"

type GitlabOp struct {
	issuer                    string // Change issuer to point this to a test issuer
	publicKeyFinder           discover.PublicKeyFinder
	tokenEnvVar               string
	requestTokensOverrideFunc func(string) (*jwsig.Tokens, error)
}

func NewGitlabOpFromEnvironmentDefault() *GitlabOp {
	return NewGitlabOpFromEnvironment("OPENPUBKEY_JWT")
}

func NewGitlabOpFromEnvironment(tokenEnvVar string) *GitlabOp {
	return NewGitlabOp(gitlabIssuer, tokenEnvVar)
}

func NewGitlabOp(issuer string, tokenEnvVar string) *GitlabOp {
	op := &GitlabOp{
		issuer:                    issuer,
		publicKeyFinder:           *discover.DefaultPubkeyFinder(),
		tokenEnvVar:               tokenEnvVar,
		requestTokensOverrideFunc: nil,
	}
	return op
}

func (g *GitlabOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByToken(ctx, g.issuer, token)
}

func (g *GitlabOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByKeyID(ctx, g.issuer, keyID)
}

func (g *GitlabOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*jwsig.Tokens, error) {
	// Define our commitment as the hash of the client instance claims
	cicHash, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}

	var idToken []byte
	if g.requestTokensOverrideFunc != nil {
		noCicHashInIDToken := ""
		if tokens, err := g.requestTokensOverrideFunc(noCicHashInIDToken); err != nil {
			return nil, fmt.Errorf("error requesting ID Token: %w", err)
		} else {
			idToken = tokens.IDToken
		}
	} else {
		idTokenStr, err := getEnvVar(g.tokenEnvVar)
		if err != nil {
			return nil, fmt.Errorf("error requesting ID Token: %w", err)
		}
		idToken = []byte(idTokenStr)
	}
	// idTokenLB is the ID Token in a memguard LockedBuffer, this is done
	// because the ID Token contains the OPs RSA signature which is a secret
	// in GQ signatures. For non-GQ signatures OPs RSA signature is considered
	// a public value.
	idTokenLB := memguard.NewBufferFromBytes([]byte(idToken))
	defer idTokenLB.Destroy()
	gqToken, err := CreateGQBoundToken(ctx, idTokenLB.Bytes(), g, string(cicHash))
	if err != nil {
		return nil, err
	}
	return &jwsig.Tokens{IDToken: []byte(gqToken)}, nil
}

func (g *GitlabOp) Issuer() string {
	return g.issuer
}

func (g *GitlabOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	vp := NewProviderVerifier(g.issuer,
		ProviderVerifierOpts{CommitType: CommitTypesEnum.GQ_BOUND, GQOnly: true, SkipClientIDCheck: true},
	)
	return vp.VerifyIDToken(ctx, idt, cic)
}
