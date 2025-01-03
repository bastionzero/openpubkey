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

package jwsig

import (
	"fmt"
)

type Jws struct {
	Payload    string      `json:"payload"`    // Base64 encoded
	Signatures []Signature `json:"signatures"` // Base64 encoded
}

type SigOptStruct struct {
	PublicHeader map[string]any
}
type SigOpts func(a *SigOptStruct)

// WithPublicHeader species that a public header be included in the
// signature. Public headers aren't Base64 encoded because they aren't signed.
// Example use: WithPublicHeader(map[string]any{"key1": "abc", "key2": "def"})
func WithPublicHeader(publicHeader map[string]any) SigOpts {
	return func(o *SigOptStruct) {
		o.PublicHeader = publicHeader
	}
}

func (j *Jws) AddSignature(token []byte, opts ...SigOpts) error {
	sigOpts := &SigOptStruct{}
	for _, applyOpt := range opts {
		applyOpt(sigOpts)
	}

	protected, payload, signature, err := SplitCompact(token)
	if err != nil {
		return err
	}
	if j.Payload != string(payload) {
		return fmt.Errorf("payload in compact token does not match existing payload in jws, expected=(%s), got=(%s)",
			string(j.Payload),
			string(payload))
	}
	sig := Signature{
		Protected: string(protected),
		Public:    sigOpts.PublicHeader,
		Signature: string(signature),
	}

	if j.Signatures == nil {
		j.Signatures = []Signature{}
	}
	j.Signatures = append(j.Signatures, sig)

	return nil
}

func (j *Jws) GetToken(i int) ([]byte, error) {
	if i < len(j.Signatures) && i >= 0 {
		return []byte(j.Signatures[i].Protected + "." + j.Payload + "." + j.Signatures[i].Signature), nil
	} else {
		return nil, fmt.Errorf("no signature at index i (%d), len(signatures) (%d)", i, len(j.Signatures))
	}
}

func (j *Jws) GetTokenByTyp(typ string) ([]byte, error) {
	matchingTokens := []Signature{}
	for _, v := range j.Signatures {
		if typFound, err := v.GetTyp(); err != nil {
			return nil, err
		} else {
			// Both the JWS standard and the OIDC standard states that typ is case sensitive
			// so we treat it as case sensitive as well
			//
			// "The typ (type) header parameter is used to declare the type of the
			// signed content. The typ value is case sensitive."
			// https://openid.net/specs/draft-jones-json-web-signature-04.html#ReservedHeaderParameterName
			//
			// "The "typ" (type) Header Parameter is used by JWS applications to
			// declare the media type [IANA.MediaTypes] of this complete JWS.
			// [..] Per RFC 2045 [RFC2045], all media type values, subtype values, and
			// parameter names are case insensitive. However, parameter values are case
			// sensitive unless otherwise specified for the specific parameter."
			// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.9
			if typFound == typ {
				matchingTokens = append(matchingTokens, v)
			}
		}
	}
	if len(matchingTokens) > 1 {
		// Currently we only have one token per token typ. We can change this later
		// for COS tokens. This check prevents hidden tokens, where one token of
		// the same typ hides another token of the same typ.
		return nil, fmt.Errorf("more than one token found, all current token typs are unique")
	} else if len(matchingTokens) == 0 {
		// if typ not found return nil
		return nil, nil
	} else {
		return []byte(matchingTokens[0].Protected + "." + j.Payload + "." + matchingTokens[0].Signature), nil
	}
}
