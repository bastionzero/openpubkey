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

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/jwsig"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers/mocks"
)

const mockProviderIssuer = "https://accounts.example.com"

var _ OpenIdProvider = (*MockProvider)(nil)

type MockProviderOpts struct {
	Issuer     string
	ClientID   string
	GQSign     bool
	NumKeys    int
	CommitType CommitType
	// We keep VerifierOpts as a variable separate to let us test failures
	// where the mock op does something which causes a verification failure
	VerifierOpts ProviderVerifierOpts
}

func DefaultMockProviderOpts() MockProviderOpts {
	clientID := "test_client_id"
	return MockProviderOpts{
		Issuer:     "https://accounts.example.com",
		ClientID:   clientID,
		GQSign:     false,
		NumKeys:    2,
		CommitType: CommitTypesEnum.NONCE_CLAIM,
		VerifierOpts: ProviderVerifierOpts{
			CommitType:        CommitTypesEnum.NONCE_CLAIM,
			ClientID:          clientID,
			SkipClientIDCheck: false,
			GQOnly:            false,
		},
	}
}

type MockProvider struct {
	options                   MockProviderOpts
	issuer                    string
	publicKeyFinder           discover.PublicKeyFinder
	requestTokensOverrideFunc func(string) (*jwsig.Tokens, error)
}

// NewMockProvider creates a new mock provider with a random signing key and a random key ID. It returns the provider,
// the mock backend, and the ID token template. Tests can use the mock backend to look up keys issued by the mock provider.
// Tests can use the ID token template to create ID tokens and test the provider's behavior when verifying incorrectly set ID Tokens.
func NewMockProvider(opts MockProviderOpts) (*MockProvider, *mocks.MockProviderBackend, *mocks.IDTokenTemplate, error) {
	if opts.Issuer == "" {
		opts.Issuer = mockProviderIssuer
	}
	mockBackend, err := mocks.NewMockProviderBackend(opts.Issuer, opts.NumKeys)
	if err != nil {
		return nil, nil, nil, err
	}
	provider := &MockProvider{
		options:                   opts,
		issuer:                    mockBackend.Issuer,
		requestTokensOverrideFunc: mockBackend.RequestTokensOverrideFunc,
		publicKeyFinder:           mockBackend.PublicKeyFinder,
	}

	providerSigner, keyID, record := mockBackend.RandomSigningKey()
	commitmentFunc := mocks.NoClaimCommit
	if opts.CommitType.Claim == "nonce" {
		commitmentFunc = mocks.AddNonceCommit
	} else if opts.CommitType.Claim == "aud" {
		commitmentFunc = mocks.AddAudCommit
	}
	idTokenTemplate := &mocks.IDTokenTemplate{
		CommitFunc: commitmentFunc,
		Issuer:     provider.Issuer(),
		Nonce:      "empty",
		NoNonce:    false,
		Aud:        opts.ClientID,
		KeyID:      keyID,
		NoKeyID:    false,
		Alg:        record.Alg,
		NoAlg:      false,
		SigningKey: providerSigner,
	}
	if opts.CommitType.GQCommitment {
		idTokenTemplate.Aud = AudPrefixForGQCommitment
	}

	mockBackend.SetIDTokenTemplate(idTokenTemplate)
	return provider, mockBackend, idTokenTemplate, nil
}

func (m *MockProvider) requestTokens(_ context.Context, cicHash string) (*jwsig.Tokens, error) {
	return m.requestTokensOverrideFunc(cicHash)
}

func (m *MockProvider) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*jwsig.Tokens, error) {
	if m.options.CommitType.GQCommitment && !m.options.GQSign {
		// Catch misconfigurations in tests
		return nil, fmt.Errorf("if GQCommitment is true then GQSign must also be true")
	}

	// Define our commitment as the hash of the client instance claims
	cicHash, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}
	tokens, err := m.requestTokens(ctx, string(cicHash))
	if err != nil {
		return nil, err
	}
	if m.options.CommitType.GQCommitment {
		if tokens.IDToken, err = CreateGQBoundToken(ctx, tokens.IDToken, m, string(cicHash)); err != nil {
			return nil, err
		}
	} else if m.options.GQSign {
		if tokens.IDToken, err = CreateGQToken(ctx, tokens.IDToken, m); err != nil {
			return nil, err
		}
	}
	return tokens, nil
}

func (m *MockProvider) RefreshTokens(ctx context.Context, _ []byte) (*jwsig.Tokens, error) {
	tokens, err := m.requestTokensOverrideFunc("")
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func (m *MockProvider) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return m.publicKeyFinder.ByToken(ctx, m.issuer, token)
}

func (m *MockProvider) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return m.publicKeyFinder.ByKeyID(ctx, m.issuer, keyID)
}

func (m *MockProvider) Issuer() string {
	return m.issuer
}

func (m *MockProvider) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	m.options.VerifierOpts.DiscoverPublicKey = &m.publicKeyFinder //TODO: this should be set in the constructor once we have constructors for each OP
	return NewProviderVerifier(m.Issuer(), m.options.VerifierOpts).VerifyIDToken(ctx, idt, cic)
}

func (m *MockProvider) VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error {
	if err := jwsig.SameIdentity(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token is for different subject than original ID Token: %w", err)
	}
	if err := jwsig.RequireOlder(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token should not be issued before original ID Token: %w", err)
	}

	pkr, err := m.publicKeyFinder.ByToken(ctx, m.Issuer(), reIdt)
	if err != nil {
		return err
	}
	alg := jwa.SignatureAlgorithm(pkr.Alg)
	if _, err := jws.Verify(reIdt, jws.WithKey(alg, pkr.PublicKey)); err != nil {
		return err
	}

	return nil
}

// Mock provider that does not support refresh
type NonRefreshableOp struct {
	op *MockProvider
}

func NewNonRefreshableOp(op *MockProvider) *NonRefreshableOp {
	return &NonRefreshableOp{op: op}
}

func (nro *NonRefreshableOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*jwsig.Tokens, error) {
	tokens, err := nro.op.RequestTokens(ctx, cic)
	return &jwsig.Tokens{IDToken: tokens.IDToken}, err
}
func (nro *NonRefreshableOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return nro.op.PublicKeyByKeyId(ctx, keyID)
}
func (nro *NonRefreshableOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return nro.op.PublicKeyByToken(ctx, token)
}
func (nro *NonRefreshableOp) Issuer() string {
	return nro.op.Issuer()
}
func (nro *NonRefreshableOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	return nro.op.VerifyIDToken(ctx, idt, cic)
}
