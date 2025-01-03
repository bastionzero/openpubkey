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
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/jwsig"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
)

const googleIssuer = "https://accounts.google.com"

// GoogleOptions is an options struct that configures how providers.GoogleOp
// operates. See providers.GetDefaultGoogleOpOptions for the recommended default
// values to use when interacting with Google as the OpenIdProvider.
type GoogleOptions struct {
	// ClientID is the client ID of the OIDC application. It should be the
	// expected "aud" claim in received ID tokens from the OP.
	ClientID string
	// ClientSecret is the client secret of the OIDC application. Some OPs do
	// not require that this value is set.
	ClientSecret string
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
}

type GoogleOp struct {
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
	requestTokensOverrideFunc func(string) (*jwsig.Tokens, error)
	httpSessionHook           http.HandlerFunc
}

func GetDefaultGoogleOpOptions() *GoogleOptions {
	return &GoogleOptions{
		Issuer:   googleIssuer,
		ClientID: "992028499768-ce9juclb3vvckh23r83fjkmvf1lvjq18.apps.googleusercontent.com",
		// The clientSecret was intentionally checked in. It holds no power. Do not report as a security issue
		// Google requires a ClientSecret even if this a public OIDC App
		ClientSecret: "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", // The client secret is a public value
		Scopes:       []string{"openid profile email"},
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

// NewGoogleOp creates a Google OP (OpenID Provider) using the
// default configurations options. It uses the OIDC Relying Party (Client)
// setup by the OpenPubkey project.
func NewGoogleOp() OpenIdProvider {
	options := GetDefaultGoogleOpOptions()
	return NewGoogleOpWithOptions(options)
}

// NewGoogleOpWithOptions creates a Google OP with configuration specified
// using an options struct. This is useful if you want to use your own OIDC
// Client or override the configuration.
func NewGoogleOpWithOptions(opts *GoogleOptions) *GoogleOp {
	return &GoogleOp{
		ClientID:                  opts.ClientID,
		ClientSecret:              opts.ClientSecret,
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

var _ OpenIdProvider = (*GoogleOp)(nil)
var _ BrowserOpenIdProvider = (*GoogleOp)(nil)
var _ RefreshableOpenIdProvider = (*GoogleOp)(nil)

func (g *GoogleOp) requestTokens(ctx context.Context, cicHash string) (*jwsig.Tokens, error) {
	if g.requestTokensOverrideFunc != nil {
		return g.requestTokensOverrideFunc(cicHash)
	}

	redirectURI, ln, err := FindAvailablePort(g.RedirectURIs)
	if err != nil {
		return nil, err
	}
	logrus.Infof("listening on http://%s/", ln.Addr().String())
	logrus.Info("press ctrl+c to stop")

	mux := http.NewServeMux()
	g.server = &http.Server{Handler: mux}

	cookieHandler, err := configCookieHandler()
	if err != nil {
		return nil, err
	}
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(g.IssuedAtOffset), rp.WithNonce(
				func(ctx context.Context) string { return cicHash })),
	}
	options = append(options, rp.WithPKCE(cookieHandler))
	if g.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(g.HttpClient))
	}

	// The reason we don't set the relyingParty on the struct and reuse it,
	// is because refresh requests require a slightly different set of
	// options. For instance we want the option to check the nonce (WithNonce)
	// here, but in RefreshTokens we don't want that option set because
	// a refreshed ID token doesn't have a nonce.
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx,
		g.issuer, g.ClientID, g.ClientSecret, redirectURI.String(),
		g.Scopes, options...)
	if err != nil {
		return nil, fmt.Errorf("error creating provider: %w", err)
	}

	state := func() string {
		return uuid.New().String()
	}

	shutdownServer := func() {
		if err := g.server.Shutdown(ctx); err != nil {
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
		rp.WithPromptURLParam("select_account"),
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
		if g.httpSessionHook != nil {
			g.httpSessionHook(w, r)
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
		err := g.server.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			logrus.Error(err)
		}
	}()

	if g.OpenBrowser {
		loginURI := fmt.Sprintf("http://localhost:%s/login", redirectURI.Port())
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
	if g.httpSessionHook == nil {
		defer shutdownServer()
	}
	select {
	case err := <-chErr:
		if g.httpSessionHook != nil {
			defer shutdownServer()
		}
		return nil, err
	case retTokens := <-chTokens:
		// retTokens is a zitadel/oidc struct. We turn it into our simpler token struct
		return &jwsig.Tokens{
			IDToken:      []byte(retTokens.IDToken),
			RefreshToken: []byte(retTokens.RefreshToken),
			AccessToken:  []byte(retTokens.AccessToken)}, nil
	}
}

func (g *GoogleOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*jwsig.Tokens, error) {
	// Define our commitment as the hash of the client instance claims
	cicHash, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}
	tokens, err := g.requestTokens(ctx, string(cicHash))
	if err != nil {
		return nil, err
	}
	if g.GQSign {
		idToken := tokens.IDToken
		if gqToken, err := CreateGQToken(ctx, idToken, g); err != nil {
			return nil, err
		} else {
			tokens.IDToken = gqToken
			return tokens, nil
		}
	}
	return tokens, nil
}

func (g *GoogleOp) RefreshTokens(ctx context.Context, refreshToken []byte) (*jwsig.Tokens, error) {
	cookieHandler, err := configCookieHandler()
	if err != nil {
		return nil, err
	}
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(g.IssuedAtOffset),
			rp.WithNonce(nil), // disable nonce check
		),
	}
	options = append(options, rp.WithPKCE(cookieHandler))
	if g.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(g.HttpClient))
	}

	// The redirect URI is not sent in the refresh request so we set it to an empty string.
	// According to the OIDC spec the only values send on a refresh request are:
	// client_id, client_secret, grant_type, refresh_token, and scope.
	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
	redirectURI := ""
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, g.issuer, g.ClientID,
		g.ClientSecret, redirectURI, g.Scopes, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create RP to verify token: %w", err)
	}
	retTokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relyingParty, string(refreshToken), "", "")
	if err != nil {
		return nil, err
	}

	if retTokens.RefreshToken == "" {
		// Google does not rotate refresh tokens, the one you get at the
		// beginning is the only one you'll ever get
		retTokens.RefreshToken = string(refreshToken)
	}

	return &jwsig.Tokens{
		IDToken:      []byte(retTokens.IDToken),
		RefreshToken: []byte(retTokens.RefreshToken),
		AccessToken:  []byte(retTokens.AccessToken)}, nil
}

func (g *GoogleOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByToken(ctx, g.issuer, token)
}

func (g *GoogleOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return g.publicKeyFinder.ByKeyID(ctx, g.issuer, keyID)
}

func (g *GoogleOp) Issuer() string {
	return g.issuer
}

func (g *GoogleOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	vp := NewProviderVerifier(g.issuer, ProviderVerifierOpts{CommitType: CommitTypesEnum.NONCE_CLAIM, ClientID: g.ClientID, DiscoverPublicKey: &g.publicKeyFinder})
	return vp.VerifyIDToken(ctx, idt, cic)
}

func (g *GoogleOp) VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error {
	if err := jwsig.SameIdentity(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token is for different subject than original ID Token: %w", err)
	}
	if err := jwsig.RequireOlder(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token should not be issued before original ID Token: %w", err)
	}

	options := []rp.Option{}
	if g.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(g.HttpClient))
	}
	redirectURI := ""
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, g.issuer, g.ClientID,
		g.ClientSecret, redirectURI, g.Scopes, options...)
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
func (g *GoogleOp) HookHTTPSession(h http.HandlerFunc) {
	g.httpSessionHook = h
}

// FindAvailablePort attempts to open a listener on localhost until it finds one or runs out of redirectURIs to try
func FindAvailablePort(redirectURIs []string) (*url.URL, net.Listener, error) {
	var ln net.Listener
	var lnErr error
	for _, v := range redirectURIs {
		redirectURI, err := url.Parse(v)
		if err != nil {
			return nil, nil, fmt.Errorf("malformed redirectURI specified, redirectURI was %s", v)
		}

		lnStr := fmt.Sprintf("localhost:%s", redirectURI.Port())
		ln, lnErr = net.Listen("tcp", lnStr)
		if lnErr == nil {
			return redirectURI, ln, nil
		}
	}
	return nil, nil, fmt.Errorf("failed to start a listener for the callback from the OP, got %w", lnErr)
}

func configCookieHandler() (*httphelper.CookieHandler, error) {
	// I've been unable to determine a scenario in which setting a hashKey and blockKey
	// on the cookie provide protection in the localhost redirect URI case. However I
	// see no harm in setting it.
	hashKey := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, hashKey); err != nil {
		return nil, fmt.Errorf("failed to generate random keys for cookie storage")
	}
	blockKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, blockKey); err != nil {
		return nil, fmt.Errorf("failed to generate random keys for cookie storage")
	}

	// OpenPubkey uses a localhost redirect URI to receive the authcode
	// from the OP. Localhost redirects use http not https. Thus, we should
	// not set these cookies as secure-only. This should be changed if
	// OpenPubkey added support for non-localhost redirect URIs.
	// WithUnsecure() is equivalent to not setting the 'secure' attribute
	// flag in an HTTP Set-Cookie header (see https://http.dev/set-cookie#secure)
	return httphelper.NewCookieHandler(hashKey, blockKey, httphelper.WithUnsecure()), nil
}
