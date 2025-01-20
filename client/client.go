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

package client

import (
	"context"
	"crypto"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/openpubkey/openpubkey/verifier"
)

type OpenIdProvider = providers.OpenIdProvider

type BrowserOpenIdProvider = providers.BrowserOpenIdProvider

type PKTokenVerifier interface {
	VerifyPKToken(ctx context.Context, pkt *pktoken.PKToken, extraChecks ...verifier.Check) error
}

type OpkClient struct {
	Op           OpenIdProvider
	cosP         *CosignerProvider
	signer       crypto.Signer
	alg          jwa.KeyAlgorithm
	pkToken      *pktoken.PKToken
	refreshToken []byte
	accessToken  []byte
}

// ClientOpts contains options for constructing an OpkClient
type ClientOpts func(o *OpkClient)

// WithSigner allows the caller to inject their own signer and algorithm.
// Use this option if to generate to bring your own user key pair. If this
// option is not set the OpkClient constructor will automatically generate
// a signer, i.e., key pair.
// Example use:
//
//	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//	WithSigner(signer, jwa.ES256)
func WithSigner(signer crypto.Signer, alg jwa.KeyAlgorithm) ClientOpts {
	return func(o *OpkClient) {
		o.signer = signer
		o.alg = alg
	}
}

// WithCosignerProvider specifies what cosigner provider should be used to
// cosign the PK Token. If this is not specified then the cosigning setup
// is skipped.
func WithCosignerProvider(cosP *CosignerProvider) ClientOpts {
	return func(o *OpkClient) {
		o.cosP = cosP
	}
}

// New returns a new client.OpkClient. The op argument should be the
// OpenID Provider you want to authenticate against.
func New(op OpenIdProvider, opts ...ClientOpts) (*OpkClient, error) {
	client := &OpkClient{
		Op:     op,
		signer: nil,
		alg:    nil,
	}

	for _, applyOpt := range opts {
		applyOpt(client)
	}

	if client.alg == nil && client.signer != nil {
		return nil, fmt.Errorf("signer specified but alg is nil, must specify alg of signer")
	}

	if client.signer == nil {
		// Generate signer for specified alg. If no alg specified, defaults to ES256
		if client.alg == nil {
			client.alg = jwa.ES256
		}

		signer, err := util.GenKeyPair(client.alg)
		if err != nil {
			return nil, fmt.Errorf("failed to create key pair for client: %w ", err)
		}
		client.signer = signer
	}

	return client, nil
}

type AuthOptsStruct struct {
	extraClaims map[string]any
}
type AuthOpts func(a *AuthOptsStruct)

// WithExtraClaim specifies additional values to be included in the
// CIC. These claims will be include in the CIC protected header and
// will be hashed into the commitment claim in the ID Token. The
// commitment claim is typically the nonce or aud claim in the ID Token.
// Example use:
//
//	WithExtraClaim("claimKey", "claimValue")
func WithExtraClaim(k string, v string) AuthOpts {
	return func(a *AuthOptsStruct) {
		if a.extraClaims == nil {
			a.extraClaims = map[string]any{}
		}
		a.extraClaims[k] = v
	}
}

// Auth returns a PK Token by running the OpenPubkey protocol. It will first
// authenticate to the configured OpenID Provider (OP) and receive an ID Token.
// Using this ID Token it will generate a PK Token. If a Cosigner has been
// configured it will also attempt to get the PK Token cosigned.
func (o *OpkClient) Auth(ctx context.Context, opts ...AuthOpts) (*pktoken.PKToken, error) {
	authOpts := &AuthOptsStruct{
		extraClaims: map[string]any{},
	}
	for _, applyOpt := range opts {
		applyOpt(authOpts)
	}

	// If no Cosigner is set then do standard OIDC authentication
	if o.cosP == nil {
		pkt, err := o.oidcAuth(ctx, o.signer, o.alg, authOpts.extraClaims)
		if err != nil {
			return nil, err
		}
		o.pkToken = pkt
		return o.pkToken.DeepCopy()
	}

	// If a Cosigner is set then check that will support doing Cosigner auth
	if browserOp, ok := o.Op.(BrowserOpenIdProvider); !ok {
		return nil, fmt.Errorf("OP supplied does not have support for MFA Cosigner")
	} else {
		redirCh := make(chan string, 1)

		browserOp.HookHTTPSession(func(w http.ResponseWriter, r *http.Request) {
			redirectUri := <-redirCh
			http.Redirect(w, r, redirectUri, http.StatusFound)
		})

		pkt, err := o.oidcAuth(ctx, o.signer, o.alg, authOpts.extraClaims)
		if err != nil {
			return nil, err
		}
		pktCos, err := o.cosP.RequestToken(ctx, o.signer, pkt, redirCh)
		if err != nil {
			return nil, err
		}
		o.pkToken = pktCos
		return o.pkToken.DeepCopy()
	}
}

// oidcAuth performs the OpenIdConnect part of the protocol.
// Auth is the exposed function that should be called.
func (o *OpkClient) oidcAuth(
	ctx context.Context,
	signer crypto.Signer,
	alg jwa.KeyAlgorithm,
	extraClaims map[string]any,
) (*pktoken.PKToken, error) {
	// keep track of any additional verifierChecks for the verifier
	verifierChecks := []verifier.Check{}

	// Use our signing key to generate a JWK key and set the "alg" header
	jwkKey, err := jwk.PublicKeyOf(signer)
	if err != nil {
		return nil, err
	}
	err = jwkKey.Set(jwk.AlgorithmKey, alg)
	if err != nil {
		return nil, err
	}

	// Use provided public key to generate client instance claims
	cic, err := clientinstance.NewClaims(jwkKey, extraClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate client instance claims: %w", err)
	}

	tokens, err := o.Op.RequestTokens(ctx, cic)
	if err != nil {
		return nil, fmt.Errorf("error requesting OIDC tokens from OpenID Provider: %w", err)
	}
	idToken := tokens.IDToken
	o.refreshToken = tokens.RefreshToken
	o.accessToken = tokens.AccessToken

	// Sign over the payload from the ID token and client instance claims
	cicToken, err := cic.Sign(signer, alg, idToken)
	if err != nil {
		return nil, fmt.Errorf("error creating cic token: %w", err)
	}

	// Combine our ID token and signature over the cic to create our PK Token
	pkt, err := pktoken.New(idToken, cicToken)
	if err != nil {
		return nil, fmt.Errorf("error creating PK Token: %w", err)
	}

	pktVerifier, err := verifier.New(o.Op)
	if err != nil {
		return nil, err
	}

	if err := pktVerifier.VerifyPKToken(ctx, pkt, verifierChecks...); err != nil {
		return nil, fmt.Errorf("error verifying PK Token: %w", err)
	}
	return pkt, nil
}

// Refresh uses a Refresh Token to request a fresh ID Token and Access Token from an OpenID Provider.
// It provides a way to refresh the Access and ID Tokens for an OpenID Provider that supports refresh requests,
// allowing the client to continue making authenticated requests without requiring the user to re-authenticate.
func (o *OpkClient) Refresh(ctx context.Context) (*pktoken.PKToken, error) {
	if tokensOp, ok := o.Op.(providers.RefreshableOpenIdProvider); ok {
		if o.refreshToken == nil {
			return nil, fmt.Errorf("no refresh token set")
		}
		if o.pkToken == nil {
			return nil, fmt.Errorf("no PK Token set, run Auth() to create a PK Token first")
		}
		tokens, err := tokensOp.RefreshTokens(ctx, o.refreshToken)
		if err != nil {
			return nil, fmt.Errorf("error requesting ID token: %w", err)
		}
		o.pkToken.FreshIDToken = tokens.IDToken
		o.refreshToken = tokens.RefreshToken
		o.accessToken = tokens.AccessToken

		return o.pkToken.DeepCopy()
	}
	return nil, fmt.Errorf("OP (issuer=%s) does not support OIDC refresh requests", o.Op.Issuer())
}

// GetOp returns the OpenID Provider the OpkClient has been configured to use
func (o *OpkClient) GetOp() OpenIdProvider {
	return o.Op
}

// GetCosP returns the MFA Cosigner Provider the OpkClient has been
// configured to use
func (o *OpkClient) GetCosP() *CosignerProvider {
	return o.cosP
}

// GetSigner returns the client's key pair (Public Key, Signing Key)
func (o *OpkClient) GetSigner() crypto.Signer {
	return o.signer
}

// GetAlg returns the algorithm of the client's key pair
// (Public Key, Signing Key)
func (o *OpkClient) GetAlg() jwa.KeyAlgorithm {
	return o.alg
}

func (o *OpkClient) SetPKToken(pkt *pktoken.PKToken) {
	o.pkToken = pkt
}

// GetPKToken returns a deep copy of client's current PK Token
func (o *OpkClient) GetPKToken() (*pktoken.PKToken, error) {
	return o.pkToken.DeepCopy()
}
