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

package mfacosigner

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/examples/mfa/mfacosigner/jwks"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

type Server struct {
	cosigner *MfaCosigner
	jwksUri  string
}

func NewMfaCosignerHttpServer(serverUri, rpID, rpOrigin, RPDisplayName string) (*Server, error) {
	server := &Server{}

	// WebAuthn configuration
	cfg := &webauthn.Config{
		RPDisplayName: RPDisplayName,
		RPID:          rpID,
		RPOrigin:      rpOrigin,
	}

	// Generate the key pair for our cosigner
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, err
	}

	jwksServer, kid, err := jwks.NewJwksServer(signer, alg)
	if err != nil {
		return nil, err
	}
	jwksHost := jwksServer.URI()
	server.jwksUri = fmt.Sprintf("%s/.well-known/jwks.json", jwksHost)
	issuer := rpOrigin

	fmt.Println("JWKS hosted at", server.jwksUri)
	server.cosigner, err = New(signer, alg, issuer, kid, cfg)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	// Static assets don't need to be URL versioned as mfa-auth-init
	// can redirect to the right URL as needed
	mux.Handle("/", http.FileServer(http.Dir("mfacosigner/static")))
	mux.HandleFunc("/v1/mfa-auth-init", server.initAuth)
	mux.HandleFunc("/v1/check-registration", server.checkIfRegistered)
	mux.HandleFunc("/v1/register/begin", server.beginRegistration)
	mux.HandleFunc("/v1/register/finish", server.finishRegistration)
	mux.HandleFunc("/v1/login/begin", server.beginLogin)
	mux.HandleFunc("/v1/login/finish", server.finishLogin)
	mux.HandleFunc("/v1/sign", server.signPkt)
	mux.HandleFunc("/.well-known/openid-configuration", server.wellKnownConf)
	mux.HandleFunc("/.well-known/openpubkey-configuration", server.wellKnownConf)

	err = http.ListenAndServe(":3003", mux)
	return server, err
}

func (s *Server) URI() string {
	return s.cosigner.Issuer
}

func (s *Server) initAuth(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		return
	}
	pktB64 := []byte(r.URL.Query().Get("pkt"))
	pktJson, err := util.Base64DecodeForJWT(pktB64)
	if err != nil {
		return
	}
	var pkt *pktoken.PKToken
	if err := json.Unmarshal(pktJson, &pkt); err != nil {
		return
	}
	sig := []byte(r.URL.Query().Get("sig1"))

	authID, err := s.cosigner.InitAuth(pkt, sig)
	if err != nil {
		http.Error(w, "Error initiating authentication", http.StatusInternalServerError)
		return
	}
	mfapage := fmt.Sprintf("/?authid=%s", authID)

	http.Redirect(w, r, mfapage, http.StatusFound)
}

func (s *Server) checkIfRegistered(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}
	registered := s.cosigner.CheckIsRegistered(authID)

	response, _ := json.Marshal(map[string]bool{
		"isRegistered": registered,
	})

	w.WriteHeader(200)
	w.Write(response)
}

func GetAuthID(r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", err
	}
	return string([]byte(r.URL.Query().Get("authid"))), nil
}

func (s *Server) beginRegistration(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}

	options, err := s.cosigner.BeginRegistration(authID)

	optionsJson, err := json.Marshal(options)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(optionsJson)
}

func (s *Server) finishRegistration(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		http.Error(w, "Error in parsing credential", http.StatusInternalServerError)
		return
	}

	err = s.cosigner.FinishRegistration(authID, parsedResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(201)
	fmt.Println("MFA registration complete")
}

func (s *Server) beginLogin(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}
	options, err := s.cosigner.BeginLogin(authID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	optionsJson, err := json.Marshal(options)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(optionsJson)
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		http.Error(w, "Error in parsing credential", http.StatusInternalServerError)
		return
	}

	authcode, ruri, err := s.cosigner.FinishLogin(authID, parsedResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	redirectURIl := fmt.Sprintf("%s?authcode=%s", ruri, authcode)
	response, _ := json.Marshal(map[string]string{
		"redirect_uri": redirectURIl,
	})
	w.WriteHeader(201)
	w.Write(response)
}

func (s *Server) signPkt(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sig := []byte(r.URL.Query().Get("sig2"))

	if cosSig, err := s.cosigner.RedeemAuthcode(sig); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		cosSigB64 := util.Base64EncodeForJWT(cosSig)
		w.WriteHeader(201)
		w.Write(cosSigB64)
	}
}

func (s *Server) wellKnownConf(w http.ResponseWriter, r *http.Request) {
	type WellKnown struct {
		Issuer   string   `json:"issuer"`
		JwksUri  string   `json:"jwks_uri"`
		Versions []string `json:"versions_supported"`
	}

	wk := WellKnown{
		Issuer:   s.cosigner.Issuer,
		JwksUri:  s.jwksUri,
		Versions: []string{"v1"},
	}

	wkJson, err := json.Marshal(wk)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(200)
	w.Write(wkJson)
}
