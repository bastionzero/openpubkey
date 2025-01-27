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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/cosigner/msgs"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sirupsen/logrus"
)

type CosignerProvider struct {
	Issuer       string
	CallbackPath string
}

func (c *CosignerProvider) RequestToken(ctx context.Context, signer crypto.Signer, pkt *pktoken.PKToken, redirCh chan string) (*pktoken.PKToken, error) {
	wellKnownConf, err := c.ReqKnownConf()
	if err != nil {
		return nil, err
	}

	ver, err := c.findCompatibleVersion(wellKnownConf.Versions)
	if err != nil {
		return nil, err
	}

	switch ver {
	case "v1":
		return c.requestTokenV1(ctx, signer, pkt, redirCh)
	default:
		return nil, fmt.Errorf("cosigner protocol version '%s' is unsupported by client", ver)
	}
}

func (c *CosignerProvider) requestTokenV1(ctx context.Context, signer crypto.Signer, pkt *pktoken.PKToken, redirCh chan string) (*pktoken.PKToken, error) {
	apiBaseUrl, err := c.apiBaseUrl("v1", c.Issuer)
	if err != nil {
		return nil, err
	}

	// Find an unused port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind to an available port: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	host := fmt.Sprintf("localhost:%d", port)
	redirectURI := fmt.Sprintf("http://%s%s", host, c.CallbackPath)

	// We set the buffer size to one and then in the CallbackPath handler we
	// ensure only said either 0 or 1 message to a channel before returning.
	// This prevents blocking inside CallbackPath handler when it attempts to
	// write to the channel. If the callbackPath handler is called twice by the
	// user's web browser the second call will block on a channel until the cxt
	// is marked as done.
	sigCh := make(chan []byte, 1)
	errCh := make(chan error, 1)

	// This is where we get the authcode from the Cosigner
	mux := http.NewServeMux()
	mux.Handle(c.CallbackPath,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cosSig, err := func() ([]byte, error) {
				// Get authcode from Cosigner via Cosigner redirecting user's browser window
				params := r.URL.Query()
				if _, ok := params["authcode"]; !ok {
					return nil, fmt.Errorf("cosigner did not return an authcode in the URI")
				}
				authcode := params["authcode"][0] // This is the authcode issued by the cosigner not the OP

				// Sign authcode from cosigner under PK Token and send signed authcode to Cosigner
				sig2, err := pkt.NewSignedMessage([]byte(authcode), signer)
				if err != nil {
					return nil, fmt.Errorf("cosigner client hit error when building authcode URI: %w", err)
				}
				authcodeSigUri := c.authcodeURI(apiBaseUrl, sig2)
				res, err := http.Get(authcodeSigUri)
				if err != nil {
					return nil, fmt.Errorf("error requesting MFA cosigner signature: %w", err)
				}

				// Receive response from Cosigner that has cosigner signature on PK Token
				resBody, err := io.ReadAll(res.Body)
				if err != nil {
					return nil, fmt.Errorf("error reading MFA cosigner signature response: %w", err)
				}
				cosSig, err := util.Base64DecodeForJWT(resBody)
				if err != nil {
					return nil, fmt.Errorf("error reading MFA cosigner signature response: %w", err)
				}
				// Success
				return cosSig, nil
			}()

			if err != nil {
				// Write the error message to the user
				if _, err := w.Write([]byte(err.Error())); err != nil {
					logrus.Error(err)
				}

				select {
				case errCh <- err:
				case <-ctx.Done():
					return
				}
			} else {
				if _, err := w.Write([]byte("You may now close this window")); err != nil {
					logrus.Error(err)
				}

				select {
				case sigCh <- cosSig:
				case <-ctx.Done():
					return
				}
			}

		}),
	)

	server := &http.Server{
		Addr:    host,
		Handler: mux,
	}
	logrus.Infof("listening on http://%s/", host)
	logrus.Info("press ctrl+c to stop")
	go func() {
		err := server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			logrus.Error(err)
		}
	}()
	defer func() {
		if err := server.Shutdown(ctx); err != nil {
			logrus.Error(err)
		}
	}()

	pktJson, err := json.Marshal(pkt)
	if err != nil {
		return nil, fmt.Errorf("cosigner client hit error serializing PK Token: %w", err)
	}

	initAuthMsgJson, nonce, err := c.CreateInitAuthSig(redirectURI)
	if err != nil {
		return nil, fmt.Errorf("hit error creating init auth signed message: %w", err)
	}
	sig1, err := pkt.NewSignedMessage(initAuthMsgJson, signer)
	if err != nil {
		return nil, fmt.Errorf("cosigner client hit error init auth signed message: %w", err)
	}
	redirUri := c.initAuthURI(apiBaseUrl, pktJson, sig1)

	select {
	// Trigger redirect of user's browser window to a URI controlled by the Cosigner sending the PK Token in the URI
	case redirCh <- redirUri:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case cosSig := <-sigCh: // Received cosigner signature
		// To be safe we perform these checks before adding the cosSig to the pktoken
		if err := c.ValidateCos(cosSig, nonce, redirectURI); err != nil {
			return nil, err
		}
		if err := pkt.AddSignature(cosSig, pktoken.COS); err != nil {
			return nil, fmt.Errorf("error in adding cosigner signature to PK Token: %w", err)
		}
		return pkt, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *CosignerProvider) initAuthURI(apiURI *url.URL, pktJson []byte, sig1 []byte) string {
	pktB63 := util.Base64EncodeForJWT(pktJson)
	uri := apiURI.JoinPath("mfa-auth-init")
	v := uri.Query()
	v.Add("pkt", string(pktB63))
	v.Add("sig1", string(sig1))
	uri.RawQuery = v.Encode()

	// URI Should be: https://<issuer>/mfa-auth-init?pkt=<pktJsonB64>&sig1=<sig1>
	return uri.String()
}

// Constructs the base URI for the cosigner API calls e.g., https://cos.example.com/v1
func (c *CosignerProvider) apiBaseUrl(version string, issuer string) (*url.URL, error) {
	issuerUri, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	return issuerUri.JoinPath(version), nil
}

func (c *CosignerProvider) authcodeURI(apiUri *url.URL, sig2 []byte) string {
	uri := apiUri.JoinPath("sign")
	v := uri.Query()
	v.Add("sig2", string(sig2))
	uri.RawQuery = v.Encode()

	// URI Should be: https://<issuer>/<version>/sign?&sig2=<sig2>
	return uri.String()
}

func (c *CosignerProvider) ValidateCos(cosSig []byte, expectedNonce string, expectedRedirectURI string) error {
	cosSigParsed, err := jws.Parse(cosSig)
	if err != nil {
		return fmt.Errorf("failed to parse Cosigner signature: %w", err)
	}

	if len(cosSigParsed.Signatures()) != 1 {
		return fmt.Errorf("the Cosigner signature does not have the correct number of signatures: %w", err)
	}

	ph := cosSigParsed.Signatures()[0].ProtectedHeaders()
	nonceRet, ok := ph.Get("nonce")
	if !ok {
		return fmt.Errorf("nonce not set in Cosigner signature protected header")
	}

	if expectedNonce != nonceRet {
		return fmt.Errorf("incorrect nonce set in Cosigner signature")
	}

	ruriRet, ok := ph.Get("ruri")
	if !ok {
		return fmt.Errorf("ruri (redirect URI) not set in Cosigner signature protected header")
	}

	if expectedRedirectURI != ruriRet {
		return fmt.Errorf("unexpected ruri (redirect URI) set in Cosigner signature, got %s expected %s", ruriRet, expectedRedirectURI)
	}

	issRet, ok := ph.Get("iss")
	if !ok {
		return fmt.Errorf("iss (Cosigner Issuer) not set in Cosigner signature protected header")
	}

	if c.Issuer != issRet {
		return fmt.Errorf("unexpected iss (Cosigner Issuer) set in Cosigner signature, expected %s", c.Issuer)
	}
	return nil
}

// CreateInitAuthSig generates a random nonce, validates the redirectURI,
// creates an InitMFAAuth message, marshals it to JSON,
// and returns the JSON message along with the nonce.
func (c *CosignerProvider) CreateInitAuthSig(redirectURI string) ([]byte, string, error) {
	bits := 256
	rBytes := make([]byte, bits/8)
	if _, err := rand.Read(rBytes); err != nil {
		return nil, "", err
	}
	if !strings.HasSuffix(redirectURI, c.CallbackPath) {
		return nil, "", fmt.Errorf("redirectURI (%s) does not end in expected callbackPath (%s)", redirectURI, c.CallbackPath)
	}

	nonce := hex.EncodeToString(rBytes)

	msg := msgs.InitMFAAuth{
		Issuer:      c.Issuer,
		RedirectUri: redirectURI,
		TimeSigned:  time.Now().Unix(),
		Nonce:       nonce,
	}
	msgJson, err := json.Marshal(msg)
	if err != nil {
		return nil, "", err
	}
	return msgJson, nonce, nil
}

// TODO: have this live in one place
type WellKnown struct {
	Issuer   string   `json:"issuer"`
	JwksUri  string   `json:"jwks_uri"`
	Versions []string `json:"versions_supported"`
}

func (c *CosignerProvider) ReqKnownConf() (*WellKnown, error) {
	issuerUri, err := url.Parse(c.Issuer)
	if err != nil {
		return nil, err
	}
	wellKnownConf, err := issuerUri.JoinPath("/.well-known/openpubkey-configuration"), nil
	if err != nil {
		return nil, err
	}

	wkURI := wellKnownConf.String()
	res, err := http.Get(wkURI)
	if err != nil {
		return nil, fmt.Errorf("error requesting well-known/openpubkey-configuration: %w", err)
	}
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading well-known/openpubkey-configuration: %w", err)
	}
	var wk WellKnown
	err = json.Unmarshal(resBody, &wk)
	if err != nil {
		return nil, err
	}
	return &wk, nil
}

func (c *CosignerProvider) findCompatibleVersion(serverVersions []string) (string, error) {
	noneVer := "none"

	ourVersions := []string{"v1"}
	cosignerVersions := serverVersions

	versionToUse := noneVer
	for _, ver := range ourVersions {
		if slices.Contains(cosignerVersions, ver) {
			versionToUse = ver
		}
	}
	if versionToUse == "none" {
		return versionToUse, fmt.Errorf(
			"no compatible cosigner version, we support [%s], cosigner supports [%s]",
			strings.Join(ourVersions, ","), strings.Join(cosignerVersions, ","))
	}
	return versionToUse, nil
}
