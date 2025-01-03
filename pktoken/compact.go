// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package pktoken

import (
	"bytes"
	"fmt"

	"github.com/openpubkey/openpubkey/jwsig"
)

// CompactPKToken creates a compact representation of a PK Token from a list of tokens
func CompactPKToken(tokens [][]byte, freshIDToken []byte) ([]byte, error) {
	if len(tokens) == 0 {
		return nil, fmt.Errorf("no tokens provided")
	}

	compact := [][]byte{}
	var payload []byte
	for _, tok := range tokens {
		tokProtected, tokPayload, tokSig, err := jwsig.SplitCompact(tok)
		if err != nil {
			return nil, err
		}
		if payload != nil {
			if !bytes.Equal(payload, tokPayload) {
				return nil, fmt.Errorf("payloads in tokens are not the same got %s and %s", payload, tokPayload)
			}
		} else {
			payload = tokPayload
		}
		compact = append(compact, tokProtected, tokSig)
	}
	// prepend the payload to the front
	compact = append([][]byte{payload}, compact...)
	pktCom := bytes.Join(compact, []byte(":"))

	// If we have a refreshed ID Token, append it to the compact representation using "."
	if freshIDToken != nil {
		if len(bytes.Split(freshIDToken, []byte("."))) != 3 {
			// Compact ID Token should be reformated as Base64(protected)"."Base64(payload)"."Base64(signature)
			return nil, fmt.Errorf("invalid refreshed ID Token")
		}
		pktCom = bytes.Join([][]byte{pktCom, freshIDToken}, []byte("."))
	}
	return pktCom, nil
}

// SplitCompactPKToken breaks a compact representation of a PK Token into its constituent tokens
func SplitCompactPKToken(pktCom []byte) ([][]byte, []byte, error) {
	tokensBytes, freshIDToken, _ := bytes.Cut(pktCom, []byte("."))
	tokensParts := bytes.Split(tokensBytes, []byte(":"))

	if freshIDToken != nil && len(bytes.Split(freshIDToken, []byte("."))) != 3 {
		// Compact ID Token should be reformated as Base64(protected)"."Base64(payload)"."Base64(signature)
		return nil, nil, fmt.Errorf("invalid refreshed ID Token")
	}

	// Compact PK Token with refreshed ID Token should have at least 3 parts and should be:
	// Base64(payload)":"Base64(protected1)":"Base64(signature1)"...":"Base64(protectedN)":"Base64(signatureN)"
	if len(tokensParts) < 3 || len(tokensParts)%2 != 1 {
		return nil, nil, fmt.Errorf("invalid number of segments, got %d", len(tokensParts))
	}
	tokens := [][]byte{}
	payload := tokensParts[0]
	for i := 1; i < len(tokensParts); i += 2 {
		// We return each token in JWT compact format (Base64(protected)"."Base64(payload)"."Base64(signature))
		token := bytes.Join([][]byte{tokensParts[i], payload, tokensParts[i+1]}, []byte("."))
		tokens = append(tokens, token)
	}
	return tokens, freshIDToken, nil
}
