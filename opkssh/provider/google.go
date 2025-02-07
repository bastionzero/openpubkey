package provider

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/awnumar/memguard"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/util"
	zoidc "github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	zhttp "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var (
	defaultScopes = []string{"openid", "profile", "email"}
	loginEndpoint = "/login"
)

type GoogleProvider struct {
	issuer       string
	clientID     string
	clientSecret string
	scopes       []string

	redirectEndpoint string
	redirectURI      *url.URL
	autoOpenLoginURL bool
	httpClient       *http.Client

	tokens *oidc.Tokens[*oidc.IDTokenClaims]
}

var _ RefreshableOP = &GoogleProvider{}
var _ Config = &GoogleProvider{}

func NewGoogleProvider(
	issuer,
	clientID,
	clientSecret string,
	redirectURIPorts []int,
	redirectEndpoint string,
	scopes []string,
	autoOpenLoginURL bool,
	httpClient *http.Client,
) (*GoogleProvider, error) {
	redirectPort := redirectURIPorts[0]
	// Choose an available port if more than one was specified
	if len(redirectURIPorts) > 1 {
		if port, err := chooseAvailablePort(redirectURIPorts); err != nil {
			return nil, err
		} else {
			redirectPort = port
		}
	}

	redirectURI, err := url.ParseRequestURI(fmt.Sprintf("http://localhost:%d", redirectPort))
	if err != nil {
		return nil, err
	}
	redirectURI.Path = redirectEndpoint

	if len(scopes) == 0 {
		scopes = defaultScopes
	}

	provider := &GoogleProvider{
		issuer:           issuer,
		clientID:         clientID,
		clientSecret:     clientSecret,
		redirectEndpoint: redirectEndpoint,
		redirectURI:      redirectURI,
		autoOpenLoginURL: autoOpenLoginURL,
		httpClient:       httpClient,
		scopes:           scopes,
	}

	return provider, nil
}

func (g *GoogleProvider) RequestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error) {
	// zitadel uses gorilla securecookie under the hood for their Cookie management
	hashKey := securecookie.GenerateRandomKey(64)
	blockKey := securecookie.GenerateRandomKey(32)
	if hashKey == nil || blockKey == nil {
		return nil, fmt.Errorf("failed to generate random keys for cookie storage")
	}

	cookieHandler := zhttp.NewCookieHandler(hashKey, blockKey, zhttp.WithUnsecure())
	options := []rp.Option{
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(5*time.Second), rp.WithNonce(
				func(ctx context.Context) string { return cicHash }),
		),
		rp.WithPKCE(cookieHandler),
	}
	if g.httpClient != nil {
		options = append(options, rp.WithHTTPClient(g.httpClient))
	}

	relyingParty, err := rp.NewRelyingPartyOIDC(
		ctx,
		g.issuer,
		g.clientID,
		g.clientSecret,
		g.redirectURI.String(),
		g.scopes,
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating relying party: %w", err)
	}

	tokenChan := make(chan *oidc.Tokens[*oidc.IDTokenClaims])
	handleTokens := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		tokenChan <- tokens
		msg := "<p><strong>Success!</strong></p>"
		msg = msg + "<p>You are authenticated and can now return to the CLI.</p>"
		w.Write([]byte(msg))
	}

	mux := http.NewServeMux()
	mux.Handle(g.redirectEndpoint, rp.CodeExchangeHandler(handleTokens, relyingParty))
	mux.Handle(loginEndpoint, rp.AuthURLHandler(
		func() string { return uuid.New().String() },
		relyingParty,
		rp.WithPromptURLParam("consent"),
		rp.WithURLParam("nonce", cicHash),
		rp.WithURLParam("access_type", "offline")),
	)
	server := &http.Server{
		Addr:    fmt.Sprintf("localhost:%s", g.redirectURI.Port()),
		Handler: mux,
	}
	go func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Println(err)
		}
	}()
	defer server.Shutdown(ctx)

	// auto-open the url
	if g.autoOpenLoginURL {
		earl := fmt.Sprintf("http://%s%s", server.Addr, loginEndpoint)
		util.OpenUrl(earl)
	}

	// Wait until we receive the ID token and then exit
	select {
	case token := <-tokenChan:
		g.tokens = token
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return memguard.NewBufferFromBytes([]byte(g.tokens.IDToken)), nil
}

func (g *GoogleProvider) Refresh(ctx context.Context) (*memguard.LockedBuffer, error) {
	options := []rp.Option{}
	if g.httpClient != nil {
		options = append(options, rp.WithHTTPClient(g.httpClient))
	}

	provider, err := rp.NewRelyingPartyOIDC(
		ctx,
		g.issuer,
		g.clientID,
		g.clientSecret,
		g.redirectURI.String(),
		g.scopes,
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create RP to verify token: %w", err)
	}

	refreshToken := g.tokens.RefreshToken
	g.tokens, err = rp.RefreshTokens[*oidc.IDTokenClaims](ctx, provider, g.tokens.RefreshToken, "", "")
	if err != nil {
		return nil, err
	}

	// Google does not rotate refresh tokens, the one you get at the beginning is the only one you'll ever get
	g.tokens.RefreshToken = refreshToken

	return memguard.NewBufferFromBytes([]byte(g.tokens.IDToken)), nil
}

func (g *GoogleProvider) VerifyCICHash(ctx context.Context, idt []byte, expectedCICHash string) error {
	cicHash, err := client.ExtractClaim(idt, "nonce")
	if err != nil {
		return err
	}

	if cicHash != expectedCICHash {
		return fmt.Errorf("nonce claim doesn't match, got %q, expected %q", cicHash, expectedCICHash)
	}

	return nil
}

func (g *GoogleProvider) PublicKey(ctx context.Context, idt []byte) (crypto.PublicKey, error) {
	jwt, err := jws.Parse(idt)
	if err != nil {
		return nil, fmt.Errorf("malformatted ID token: %w", err)
	}
	kid := jwt.Signatures()[0].ProtectedHeaders().KeyID()

	provider, err := zoidc.Discover(ctx, g.issuer, zhttp.DefaultHTTPClient)
	if err != nil {
		return nil, err
	}

	jwks, err := jwk.Fetch(ctx, provider.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}

	key, ok := jwks.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("key isn't in JWKS")
	}

	pubKey := new(rsa.PublicKey)
	err = key.Raw(pubKey)
	if err != nil {
		return nil, fmt.Errorf("malformatted public key: %w", err)
	}

	return pubKey, err
}

func (g *GoogleProvider) VerifyNonGQSig(ctx context.Context, idt []byte, expectedNonce string) error {
	options := []rp.Option{
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(5*time.Second),
			rp.WithNonce(func(ctx context.Context) string { return expectedNonce }),
		),
	}
	if g.httpClient != nil {
		options = append(options, rp.WithHTTPClient(g.httpClient))
	}

	provider, err := rp.NewRelyingPartyOIDC(
		ctx,
		g.issuer,
		g.clientID,
		g.clientSecret,
		g.redirectURI.String(),
		g.scopes,
		options...,
	)
	if err != nil {
		return fmt.Errorf("failed to create RP to verify token: %w", err)
	}

	_, err = rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, string(idt), provider.IDTokenVerifier())
	if err != nil {
		return fmt.Errorf("error verifying OP signature on PK Token (ID Token invalid): %w", err)
	}

	return nil
}

func (g *GoogleProvider) ClientID() string {
	return g.clientID
}

func (g *GoogleProvider) IssuerUrl() string {
	return g.issuer
}

// Retrieve an open port
func chooseAvailablePort(possiblePorts []int) (port int, err error) {
	for _, port := range possiblePorts {
		if err := checkPortIsAvailable(port); err == nil {
			return port, nil
		}
	}

	return 0, fmt.Errorf("failed to retrieve open port: callback listener could not bind to any of the default ports")
}

// Reference -> https://gist.github.com/montanaflynn/b59c058ce2adc18f31d6
// Check if a port is available
func checkPortIsAvailable(port int) error {

	// Concatenate a colon and the port
	host := fmt.Sprintf("127.0.0.1:%d", port)
	// Try to create a server with the port
	server, err := net.Listen("tcp", host)
	// if it fails then the port is likely taken
	if err != nil {
		return err
	}

	// close the server
	server.Close()

	// we successfully used and closed the port
	// so it's now available to be used again
	return nil

}
