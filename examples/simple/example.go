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

package main

import (
	"context"
	"fmt"

	"github.com/goccy/go-json"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/jwsig"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
)

func Sign(op client.OpenIdProvider) ([]byte, []byte, error) {
	// Create a OpenPubkey client, this automatically generates a fresh
	// key pair (public key, signing key). The public key is added to any
	// PK Tokens the client generates
	opkClient, err := client.New(op)
	if err != nil {
		return nil, nil, err
	}

	// Generate a PK Token by authenticating to the OP (Google)
	pkt, err := opkClient.Auth(context.Background())
	if err != nil {
		return nil, nil, err
	}

	// Use the signing key that the client just generated to sign the message
	msg := []byte("All is discovered - flee at once")
	signedMsg, err := pkt.NewSignedMessage(msg, opkClient.GetSigner())
	if err != nil {
		return nil, nil, err
	}

	// Serialize the PK Token as JSON and distribute it with the signed message
	pktJson, err := json.Marshal(pkt)
	if err != nil {
		return nil, nil, err
	}
	return pktJson, signedMsg, nil
}

func Verify(op client.OpenIdProvider, pktJson []byte, signedMsg []byte) error {
	// Create a PK Token object from the PK Token JSON
	pkt := new(pktoken.PKToken)
	err := json.Unmarshal(pktJson, &pkt)
	if err != nil {
		return err
	}

	// Verify that PK Token is issued by the OP you wish to use
	pktVerifier, err := verifier.New(op)
	if err != nil {
		return err
	}
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	if err != nil {
		return err
	}

	// Check that the message verifies under the user's public key in the PK Token
	msg, err := pkt.VerifySignedMessage(signedMsg)
	if err != nil {
		return err
	}

	// Get the signer's email address from ID Token inside the PK Token
	idtClaims := new(jwsig.OidcClaims)
	if err := json.Unmarshal(pkt.Payload, idtClaims); err != nil {
		return err
	}

	fmt.Printf("Verification successful: %s (%s) signed the message '%s'\n", idtClaims.Email, idtClaims.Issuer, string(msg))
	return nil
}

func main() {
	opOptions := providers.GetDefaultGoogleOpOptions()
	// Change this to true to turn on GQ signatures
	opOptions.GQSign = false
	op := providers.NewGoogleOpWithOptions(opOptions)
	pktJson, signedMsg, err := Sign(op)
	if err != nil {
		fmt.Println("Failed to sign message:", err)
		return
	}
	err = Verify(op, pktJson, signedMsg)
	if err != nil {
		fmt.Println("Failed to verify message:", err)
		return
	}
}
