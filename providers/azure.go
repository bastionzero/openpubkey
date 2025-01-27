// Copyright 2025 OpenPubkey
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
	"net/http"
	"time"

	"github.com/openpubkey/openpubkey/discover"
)

// AzureOptions is an options struct that configures how providers.AzureOp
// operates. See providers.GetDefaultAzureOpOptions for the recommended default
// values to use when interacting with Azure as the OpenIdProvider.
type AzureOptions struct {
	// ClientID is the client ID of the OIDC application. It should be the
	// expected "aud" claim in received ID tokens from the OP.
	ClientID string
	// Issuer is the OP's issuer URI for performing OIDC authorization and
	// discovery.
	Issuer string
	// Scopes is the list of scopes to send to the OP in the initial
	// authorization request.
	Scopes []string
	// RedirectURIs is the list of authorized redirect URIs that can be
	// redirected to by the OP after the user completes the authorization code
	// flow exchange. Ensure that your OIDC application is configured to accept
	// these URIs otherwise an error may occur.
	RedirectURIs []string
	// GQSign denotes if the received ID token should be upgraded to a GQ token
	// using GQ signatures.
	GQSign bool
	// OpenBrowser denotes if the client's default browser should be opened
	// automatically when performing the OIDC authorization flow. This value
	// should typically be set to true, unless performing some headless
	// automation (e.g. integration tests) where you don't want the browser to
	// open.
	OpenBrowser bool
	// HttpClient is the http.Client to use when making queries to the OP (OIDC
	// code exchange, refresh, verification of ID token, fetch of JWKS endpoint,
	// etc.). If nil, then http.DefaultClient is used.
	HttpClient *http.Client
	// IssuedAtOffset configures the offset to add when validating the "iss" and
	// "exp" claims of received ID tokens from the OP.
	IssuedAtOffset time.Duration
	// TenantID is the GUID  of the Azure tenant/organization. Azure has a
	// different issuer URI for each tenant. Users that are not part of Azure
	// organization, which microsoft nicknames consumers have a default
	// tenant ID of "9188040d-6c67-4c5b-b112-36a304b66dad"
	// More details can be found at
	// https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
	TenantID string
}

func GetDefaultAzureOpOptions() *AzureOptions {
	defaultTenantID := "9188040d-6c67-4c5b-b112-36a304b66dad"
	return &AzureOptions{
		Issuer:   azureIssuer(defaultTenantID),
		ClientID: "bd345b9c-6902-400d-9e18-45abdf0f698f", // TODO: replace with a better client ID
		// Scopes:   []string{"openid profile email"},
		Scopes: []string{"openid profile email offline_access"}, // offline_access is required for refresh tokens
		RedirectURIs: []string{
			"http://localhost:3000/login-callback",
			"http://localhost:10001/login-callback",
			"http://localhost:11110/login-callback",
		},
		GQSign:         false,
		OpenBrowser:    true,
		HttpClient:     nil,
		IssuedAtOffset: 1 * time.Minute,
	}
}

// NewAzureOp creates a Azure OP (OpenID Provider) using the
// default configurations options. It uses the OIDC Relying Party (Client)
// setup by the OpenPubkey project.
func NewAzureOp() OpenIdProvider {
	options := GetDefaultAzureOpOptions()
	return NewAzureOpWithOptions(options)
}

// NewAzureOpWithOptions creates a Azure OP with configuration specified
// using an options struct. This is useful if you want to use your own OIDC
// Client or override the configuration.
func NewAzureOpWithOptions(opts *AzureOptions) *StandardOp {
	return &StandardOp{
		ClientID:                  opts.ClientID,
		Scopes:                    opts.Scopes,
		RedirectURIs:              opts.RedirectURIs,
		GQSign:                    opts.GQSign,
		OpenBrowser:               opts.OpenBrowser,
		HttpClient:                opts.HttpClient,
		IssuedAtOffset:            opts.IssuedAtOffset,
		issuer:                    opts.Issuer,
		requestTokensOverrideFunc: nil,
		publicKeyFinder: discover.PublicKeyFinder{
			JwksFunc: func(ctx context.Context, issuer string) ([]byte, error) {
				return discover.GetJwksByIssuer(ctx, issuer, opts.HttpClient)
			},
		},
	}
}

var _ OpenIdProvider = (*AzureOp)(nil)
var _ BrowserOpenIdProvider = (*AzureOp)(nil)
var _ RefreshableOpenIdProvider = (*AzureOp)(nil)

func azureIssuer(tenantID string) string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
}

type AzureOp = StandardOp
