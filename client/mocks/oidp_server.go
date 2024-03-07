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

package mocks

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

const (
	jwksEndpoint            = "/.well-known/jwks.json"
	wellKnownConfigEndpoint = "/.well-known/openid-configuration"
)

type OIDPServer struct {
	listener  net.Listener
	Server    *http.ServeMux
	uri       string
	kid       string
	jwksBytes []byte
}

// A very simple JWKS server for our MFA Cosigner example code.
func NewOIDPServer(signer crypto.Signer, alg jwa.SignatureAlgorithm) (*OIDPServer, error) {
	kid := uuid.New().String()

	// Generate our JWKS using our signing key
	jwkKey, err := jwk.PublicKeyOf(signer)
	if err != nil {
		return nil, err
	}
	jwkKey.Set(jwk.AlgorithmKey, alg)
	jwkKey.Set(jwk.KeyIDKey, kid)

	// Put our jwk into a set
	keySet := jwk.NewSet()
	keySet.AddKey(jwkKey)

	// Now convert our key set into the raw bytes for printing later
	keySetBytes, _ := json.MarshalIndent(keySet, "", "  ")
	if err != nil {
		return nil, err
	}

	s := &OIDPServer{
		Server:    http.NewServeMux(),
		jwksBytes: keySetBytes,
		kid:       kid,
	}

	// Host our JWKS at a localhost url
	s.Server.HandleFunc(jwksEndpoint, s.printJWKS)
	s.Server.HandleFunc(wellKnownConfigEndpoint, s.printWellKnownConfig)

	return s, nil
}

func (s *OIDPServer) Serve() error {
	// Find an empty port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return fmt.Errorf("failed to bind to an available port: %w", err)
	}

	s.listener = listener
	s.uri = fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port)

	go func() {
		http.Serve(listener, s.Server)
	}()

	return nil
}

func (s *OIDPServer) Shutdown() error {
	return s.listener.Close()
}

func (s *OIDPServer) KID() string {
	return s.kid
}

func (s *OIDPServer) URI() string {
	return s.uri
}

func (s *OIDPServer) printJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(s.jwksBytes)
}

func (s *OIDPServer) printWellKnownConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	config := oidc.DiscoveryConfiguration{
		Issuer:  s.uri,
		JwksURI: fmt.Sprintf("%s%s", s.uri, jwksEndpoint),
	}

	configBytes, _ := json.Marshal(config)
	w.Write(configBytes)
}
