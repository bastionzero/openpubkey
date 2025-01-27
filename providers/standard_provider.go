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
	"net/http"

	"time"

	"github.com/google/uuid"
	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type StandardOp struct {
	ClientID                  string
	ClientSecret              string
	Scopes                    []string
	RedirectURIs              []string
	GQSign                    bool
	OpenBrowser               bool
	HttpClient                *http.Client
	IssuedAtOffset            time.Duration
	issuer                    string
	server                    *http.Server
	publicKeyFinder           discover.PublicKeyFinder
	requestTokensOverrideFunc func(string) (*simpleoidc.Tokens, error)
	httpSessionHook           http.HandlerFunc
	reuseBrowserWindowHook    chan string
}

var _ OpenIdProvider = (*StandardOp)(nil)
var _ BrowserOpenIdProvider = (*StandardOp)(nil)
var _ RefreshableOpenIdProvider = (*StandardOp)(nil)

func (s *StandardOp) requestTokens(ctx context.Context, cicHash string) (*simpleoidc.Tokens, error) {
	if s.requestTokensOverrideFunc != nil {
		return s.requestTokensOverrideFunc(cicHash)
	}

	redirectURI, ln, err := FindAvailablePort(s.RedirectURIs)
	if err != nil {
		return nil, err
	}
	logrus.Infof("listening on http://%s/", ln.Addr().String())
	logrus.Info("press ctrl+c to stop")

	mux := http.NewServeMux()
	s.server = &http.Server{Handler: mux}

	cookieHandler, err := configCookieHandler()
	if err != nil {
		return nil, err
	}
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(s.IssuedAtOffset), rp.WithNonce(
				func(ctx context.Context) string { return cicHash })),
	}
	options = append(options, rp.WithPKCE(cookieHandler))
	if s.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(s.HttpClient))
	}

	// The reason we don't set the relyingParty on the struct and reuse it,
	// is because refresh requests require a slightly different set of
	// options. For instance we want the option to check the nonce (WithNonce)
	// here, but in RefreshTokens we don't want that option set because
	// a refreshed ID token doesn't have a nonce.
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx,
		s.issuer, s.ClientID, s.ClientSecret, redirectURI.String(),
		s.Scopes, options...)
	if err != nil {
		return nil, fmt.Errorf("error creating provider: %w", err)
	}

	state := func() string {
		return uuid.New().String()
	}

	shutdownServer := func() {
		if err := s.server.Shutdown(ctx); err != nil {
			logrus.Errorf("Failed to shutdown http server: %v", err)
		}
	}

	chTokens := make(chan *oidc.Tokens[*oidc.IDTokenClaims], 1)
	chErr := make(chan error, 1)

	mux.Handle("/login", rp.AuthURLHandler(state, relyingParty,
		rp.WithURLParam("nonce", cicHash),
		// Select account requires that the user click the account they want to use.
		// Results in better UX than just automatically dropping them into their
		// only signed in account.
		// See prompt parameter in OIDC spec https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
		rp.WithPromptURLParam("consent"),
		rp.WithURLParam("access_type", "offline")),
	)

	marshalToken := func(w http.ResponseWriter, r *http.Request, retTokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			chErr <- err
			return
		}

		chTokens <- retTokens

		// If defined the OIDC client hands over control of the HTTP server session to the OpenPubkey client.
		// Useful for redirecting the user's browser window that just finished OIDC Auth flow to the
		// MFA Cosigner Auth URI.
		if s.httpSessionHook != nil {
			s.httpSessionHook(w, r)
			defer shutdownServer() // If no http session hook is set, we do server shutdown in RequestTokens
		} else {
			if _, err := w.Write([]byte("You may now close this window")); err != nil {
				logrus.Error(err)
			}
		}
	}

	callbackPath := redirectURI.Path
	mux.Handle(callbackPath, rp.CodeExchangeHandler(marshalToken, relyingParty))

	go func() {
		err := s.server.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			logrus.Error(err)
		}
	}()

	loginURI := fmt.Sprintf("http://localhost:%s/login", redirectURI.Port())

	// If reuseBrowserWindowHook is set, don't open a new browser window
	// instead redirect the user's existing browser window
	if s.reuseBrowserWindowHook != nil {
		s.reuseBrowserWindowHook <- loginURI
	} else if s.OpenBrowser {
		logrus.Infof("Opening browser to on http://%s/", loginURI)
		if err := util.OpenUrl(loginURI); err != nil {
			logrus.Errorf("Failed to open url: %v", err)
		}
	}

	// If httpSessionHook is not defined shutdown the server when done,
	// otherwise keep it open for the httpSessionHook
	// If httpSessionHook is set we handle both possible cases to ensure
	// the server is shutdown:
	// 1. We shut it down if an error occurs in the marshalToken handler
	// 2. We shut it down if the marshalToken handler completes
	if s.httpSessionHook == nil {
		defer shutdownServer()
	}
	select {
	case err := <-chErr:
		if s.httpSessionHook != nil {
			defer shutdownServer()
		}
		return nil, err
	case retTokens := <-chTokens:
		// retTokens is a zitadel/oidc struct. We turn it into our simpler token struct
		return &simpleoidc.Tokens{
			IDToken:      []byte(retTokens.IDToken),
			RefreshToken: []byte(retTokens.RefreshToken),
			AccessToken:  []byte(retTokens.AccessToken)}, nil
	}
}

func (s *StandardOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	// Define our commitment as the hash of the client instance claims
	cicHash, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}
	tokens, err := s.requestTokens(ctx, string(cicHash))
	if err != nil {
		return nil, err
	}
	if s.GQSign {
		idToken := tokens.IDToken
		if gqToken, err := CreateGQToken(ctx, idToken, s); err != nil {
			return nil, err
		} else {
			tokens.IDToken = gqToken
			return tokens, nil
		}
	}
	return tokens, nil
}

func (s *StandardOp) RefreshTokens(ctx context.Context, refreshToken []byte) (*simpleoidc.Tokens, error) {
	cookieHandler, err := configCookieHandler()
	if err != nil {
		return nil, err
	}
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(s.IssuedAtOffset),
			rp.WithNonce(nil), // disable nonce check
		),
	}
	options = append(options, rp.WithPKCE(cookieHandler))
	if s.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(s.HttpClient))
	}

	// The redirect URI is not sent in the refresh request so we set it to an empty string.
	// According to the OIDC spec the only values send on a refresh request are:
	// client_id, client_secret, grant_type, refresh_token, and scope.
	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
	redirectURI := ""
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, s.issuer, s.ClientID,
		s.ClientSecret, redirectURI, s.Scopes, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create RP to verify token: %w", err)
	}
	retTokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relyingParty, string(refreshToken), "", "")
	if err != nil {
		return nil, err
	}

	if retTokens.RefreshToken == "" {
		// Google does not rotate refresh tokens, the one you get at the
		// beginning is the only one you'll ever get. This may not be true
		// of OPs.
		retTokens.RefreshToken = string(refreshToken)
	}

	return &simpleoidc.Tokens{
		IDToken:      []byte(retTokens.IDToken),
		RefreshToken: []byte(retTokens.RefreshToken),
		AccessToken:  []byte(retTokens.AccessToken)}, nil
}

func (s *StandardOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return s.publicKeyFinder.ByToken(ctx, s.issuer, token)
}

func (s *StandardOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return s.publicKeyFinder.ByKeyID(ctx, s.issuer, keyID)
}

func (s *StandardOp) Issuer() string {
	return s.issuer
}

func (s *StandardOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	vp := NewProviderVerifier(s.issuer, ProviderVerifierOpts{CommitType: CommitTypesEnum.NONCE_CLAIM, ClientID: s.ClientID, DiscoverPublicKey: &s.publicKeyFinder})
	return vp.VerifyIDToken(ctx, idt, cic)
}

func (s *StandardOp) VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error {
	if err := simpleoidc.SameIdentity(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token is for different subject than original ID Token: %w", err)
	}
	if err := simpleoidc.RequireOlder(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token should not be issued before original ID Token: %w", err)
	}

	options := []rp.Option{}
	if s.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(s.HttpClient))
	}
	redirectURI := ""
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, s.issuer, s.ClientID,
		s.ClientSecret, redirectURI, s.Scopes, options...)
	if err != nil {
		return fmt.Errorf("failed to create RP to verify token: %w", err)
	}
	_, err = rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, string(reIdt), relyingParty.IDTokenVerifier())
	return err
}

// HookHTTPSession provides a means to hook the HTTP Server session resulting
// from the OpenID Provider sending an authcode to the OIDC client by
// redirecting the user's browser with the authcode supplied in the URI.
// If this hook is set, it will be called after the receiving the authcode
// but before send an HTTP response to the user. The code which sets this hook
// can choose what HTTP response to server to the user.
//
// We use this so that we can redirect the user web browser window to
// the MFA Cosigner URI after the user finishes the OIDC Auth flow. This
// method is only available to browser based providers.
func (s *StandardOp) HookHTTPSession(h http.HandlerFunc) {
	s.httpSessionHook = h
}

// ReuseBrowserWindow is needed so that do not open more than one browser window.
// If we are using a web based OpenID Provider chooser, we have already opened one
// window on the user's browser. We should reuse that window here rather than
// opening a second browser window.
func (s *StandardOp) ReuseBrowserWindowHook(h chan string) {
	s.reuseBrowserWindowHook = h
}
