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
	"net"
	"net/http"
	"text/template"

	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sirupsen/logrus"
)

type Server struct {
}

func NewChooserServer() (*Server, error) {
	server := &Server{}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("chooser/static")))
	err := http.ListenAndServe(":3003", mux)
	return server, err
}

func NewWebChooser(opList []BrowserOpenIdProvider) *WebChooser {
	return &WebChooser{
		OpList:      opList,
		OpenBrowser: true,
	}
}

type WebChooser struct {
	OpList      []BrowserOpenIdProvider
	opSelected  BrowserOpenIdProvider
	OpenBrowser bool
}

func (wc *WebChooser) openChooser() (BrowserOpenIdProvider, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind to an available port: %w", err)
	}

	// Parse the HTML template
	tmpl := template.New("abc")
	tmpl, err = tmpl.Parse(templateHtml)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/choose", func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			GoogleUri string
		}{
			GoogleUri: "/google",
		}
		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	if wc.OpenBrowser {
		loginURI := fmt.Sprintf("http://%s/choose", listener.Addr().String())
		logrus.Infof("Opening browser to %s", loginURI)
		if err := util.OpenUrl(loginURI); err != nil {
			logrus.Errorf("Failed to open url: %v", err)
		}
	}

	opNameCh := make(chan string, 1)

	mux.HandleFunc("/google", func(w http.ResponseWriter, r *http.Request) {
		op := wc.OpList[0]
		opNameCh <- "google"

		redirCh := make(chan string, 1)
		op.ReuseBrowserWindowHook(redirCh)
		redirectUri := <-redirCh
		http.Redirect(w, r, redirectUri, http.StatusFound)
	})

	server := &http.Server{Handler: mux}
	go func() {
		err := server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			logrus.Error(err)
		}
	}()

	opName := <-opNameCh
	switch opName {
	case "google":
		return wc.OpList[0], nil
	default:
		return nil, fmt.Errorf("unknown opName: %s", opName)
	}

}

func (wc *WebChooser) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	if wc.opSelected == nil {
		var err error
		if wc.opSelected, err = wc.openChooser(); err != nil {
			return nil, err
		}
	}
	return wc.opSelected.RequestTokens(ctx, cic)
}
func (wc *WebChooser) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return wc.opSelected.PublicKeyByKeyId(ctx, keyID)
}
func (wc *WebChooser) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return wc.opSelected.PublicKeyByToken(ctx, token)
}

func (wc *WebChooser) Issuer() string {
	return wc.opSelected.Issuer()
}

func (wc *WebChooser) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	return wc.opSelected.VerifyIDToken(ctx, idt, cic)
}

func (wc *WebChooser) RefreshTokens(ctx context.Context, refreshToken []byte) (*simpleoidc.Tokens, error) {
	// In the chooser we are making assumption that all OPs in the chooser list
	// support refresh by implementing the Refresh Tokens interface.
	// TODO: Think of a better way of singling the ability to be refreshed.
	if tokensOp, ok := wc.opSelected.(RefreshableOpenIdProvider); ok {
		return tokensOp.RefreshTokens(ctx, refreshToken)
	}
	return nil, fmt.Errorf("OP (issuer=%s) does not support OIDC refresh requests", wc.opSelected.Issuer())
}

func (wc *WebChooser) VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error {
	if tokensOp, ok := wc.opSelected.(RefreshableOpenIdProvider); ok {
		return tokensOp.VerifyRefreshedIDToken(ctx, origIdt, reIdt)
	}
	return fmt.Errorf("OP (issuer=%s) does not support OIDC refresh requests", wc.opSelected.Issuer())
}

func (wc *WebChooser) HookHTTPSession(h http.HandlerFunc) {
	wc.opSelected.HookHTTPSession(h)
}

const templateHtml = `
<!DOCTYPE html>
<html>
    <head>
        <title>OpenPubkey: OpenID Providers</title>
        <style>
            body {
                text-align: center;
                font-family: Arial, sans-serif;
                background-color: #f0f0f0;
            }
            .g_id_signin {
                margin-top: 100px;
            }
        </style>
    </head>
    <body>
        <div>
        <h1>OpenPubkey OpenID Providers:</h1>
        </div>
        <br>
        <a href="{{.GoogleUri}}">
            <img src="https://developers.google.com/identity/images/btn_google_signin_dark_normal_web.png" alt="Sign in with Google" />
        </a>
    </body>
</html>`
