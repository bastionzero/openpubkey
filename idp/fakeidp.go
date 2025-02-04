package idp

import (
	"bytes"
	"crypto"
	"fmt"
	"net"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sirupsen/logrus"
)

type fakeIdp struct {
	uri         string
	signer      crypto.Signer
	alg         jwa.SignatureAlgorithm
	redirectUri string
	server      *http.Server
	port        string
	issuer      string
	jwksBytes   []byte
}

func New(redirectUri string) (*fakeIdp, error) {
	alg := jwa.RS256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, err
	}

	// TODO: Move NewJwksSet to the oidc-simple package
	keySetBytes, _, err := NewJwksSet(signer, alg)
	if err != nil {
		return nil, err
	}
	port := ":17171"
	issuer := "http://localhost" + port

	return &fakeIdp{
		alg:         alg,
		signer:      signer,
		redirectUri: redirectUri,
		port:        port,
		issuer:      issuer,
		jwksBytes:   keySetBytes,
	}, nil
}

func (o *fakeIdp) Start() error {
	listener, err := net.Listen("tcp", o.port)
	if err != nil {
		return fmt.Errorf("failed to bind to the port %s : %w", o.port, err)
	}
	o.uri = fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", o.printConfig)
	mux.HandleFunc("/.well-known/jwks.json", o.printJWKS)
	// mux.HandleFunc("/o/oauth2/v2/auth", o.auth)

	o.server = &http.Server{Handler: mux}
	go func() {
		err = o.server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			logrus.Error(err)
		}
	}()

	return nil
}

func (o *fakeIdp) printConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// TODO: Use the issuer in the struct rather than hardcoding it

	config := bytes.NewBufferString(`{
				"issuer": "http://localhost:17171",
				"authorization_endpoint": "http://localhost:17171/o/oauth2/v2/auth",
				"device_authorization_endpoint": "http://localhost:17171/device/code",
				"token_endpoint": "http://localhost:17171/token",
				"userinfo_endpoint": "http://localhost:17171/v1/userinfo",
				"revocation_endpoint": "http://localhost:17171/revoke",
				"jwks_uri": "http://localhost:17171/.well-known/jwks.json",
				"response_types_supported": [
				"code",
				"token",
				"id_token",
				"code token",
				"code id_token",
				"token id_token",
				"code token id_token",
				"none"
				],
				"subject_types_supported": [
				"public"
				],
				"id_token_signing_alg_values_supported": [
				"RS256"
				],
				"scopes_supported": [
				"openid",
				"email",
				"profile"
				],
				"token_endpoint_auth_methods_supported": [
				"client_secret_post",
				"client_secret_basic"
				],
				"claims_supported": [
				"aud",
				"email",
				"email_verified",
				"exp",
				"family_name",
				"given_name",
				"iat",
				"iss",
				"name",
				"picture",
				"sub"
				],
				"code_challenge_methods_supported": [
				"plain",
				"S256"
				],
				"grant_types_supported": [
				"authorization_code",
				"refresh_token",
				"urn:ietf:params:oauth:grant-type:device_code",
				"urn:ietf:params:oauth:grant-type:jwt-bearer"
				]
				}`)

	w.Write(config.Bytes())
}

func (o *fakeIdp) printJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(o.jwksBytes)
}

func (o *fakeIdp) SetHook(op *providers.StandardOp) {
	hookCh := make(chan string, 1)
	op.ReuseBrowserWindowHook(hookCh)

	go func() {
		select {
		case hookCalled := <-hookCh:
			logrus.Infof("Hook called with redirect URI: %s", hookCalled)
			resp, err := http.Get(o.redirectUri)
			if err != nil {
				logrus.Errorf("Failed to make HTTP request to redirect URI: %v", err)
				return
			}
			defer resp.Body.Close()
			logrus.Infof("HTTP request to redirect URI returned status: %s", resp.Status)
			return
		}
	}()
}
