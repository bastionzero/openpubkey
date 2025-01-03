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
	"fmt"
	"net/http"
	"os"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/jwsig"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

// Interface for interacting with the OP (OpenID Provider) that only returns
// an ID Token
type OpenIdProvider interface {
	RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*jwsig.Tokens, error)
	PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error)
	PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error)
	// Returns the OpenID provider issuer as seen in ID token e.g. "https://accounts.google.com"
	Issuer() string
	VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error
}

type BrowserOpenIdProvider interface {
	OpenIdProvider
	HookHTTPSession(h http.HandlerFunc)
}

// Interface for an OpenIdProvider that returns an ID Token, Refresh Token and Access Token
type RefreshableOpenIdProvider interface {
	OpenIdProvider
	RefreshTokens(ctx context.Context, refreshToken []byte) (*jwsig.Tokens, error)
	VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error
}

type CommitType struct {
	Claim        string
	GQCommitment bool
}

var CommitTypesEnum = struct {
	NONCE_CLAIM CommitType
	AUD_CLAIM   CommitType
	GQ_BOUND    CommitType
}{
	NONCE_CLAIM: CommitType{Claim: "nonce", GQCommitment: false},
	AUD_CLAIM:   CommitType{Claim: "aud", GQCommitment: false},
	GQ_BOUND:    CommitType{Claim: "", GQCommitment: true}, // The commitmentClaim is bound to the ID Token using only the GQ signature
}

func getEnvVar(name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("%q environment variable not set", name)
	}
	return value, nil
}
