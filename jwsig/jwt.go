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

type Jwt struct {
	payload       string
	payloadClaims *OidcClaims
	signature     *Signature
	raw           []byte
}

func NewJwt(token []byte) (*Jwt, error) {
	protected, payload, signature, err := SplitCompact(token)
	if err != nil {
		return nil, err
	}
	idt := &Jwt{
		payload: string(payload),
		signature: &Signature{
			Protected: string(protected),
			Signature: string(signature),
		},
		raw: token,
	}
	if err := ParseJWTSegment(protected, &idt.signature.protectedClaims); err != nil {
		return nil, fmt.Errorf("error parsing protected: %w", err)
	}
	if err := ParseJWTSegment(payload, &idt.payloadClaims); err != nil {
		return nil, fmt.Errorf("error parsing payload: %w", err)
	}
	return idt, nil
}

func (i *Jwt) GetClaims() *OidcClaims {
	return i.payloadClaims
}

func (i *Jwt) GetPayload() string {
	return i.payload
}

func (i *Jwt) GetSignature() *Signature {
	return i.signature
}

func (i *Jwt) GetRaw() []byte {
	return i.raw
}

// Compares two JWTs and determines if they are for the same identity (subject)
func SameIdentity(t1, t2 []byte) error {
	token1, err := NewJwt(t1)
	if err != nil {
		return err
	}
	token2, err := NewJwt(t2)
	if err != nil {
		return err
	}

	// Subject identity can only be established within the same issuer
	if token1.GetClaims().Issuer != token2.GetClaims().Issuer {
		return fmt.Errorf("tokens have different issuers")
	}

	if token1.GetClaims().Subject != token2.GetClaims().Subject {
		return fmt.Errorf("token have a different subject claims")
	}
	return nil
}

// RequireOlder returns an error if t1 is not older than t2
func RequireOlder(t1, t2 []byte) error {
	token1, err := NewJwt(t1)
	if err != nil {
		return err
	}
	token2, err := NewJwt(t2)
	if err != nil {
		return err
	}

	// Check which token was issued first
	if token1.GetClaims().IssuedAt > token2.GetClaims().IssuedAt {
		return fmt.Errorf("tokens not issued in correct order")
	}
	return nil
}
