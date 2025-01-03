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
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openpubkey/openpubkey/util"
)

type OidcClaims struct {
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	Audience   string `json:"-"`
	Expiration int64  `json:"exp"`
	IssuedAt   int64  `json:"iat"`
	Email      string `json:"email,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Username   string `json:"preferred_username,omitempty"`
	FirstName  string `json:"given_name,omitempty"`
	LastName   string `json:"family_name,omitempty"`
}

// Implement UnmarshalJSON for custom handling during JSON unmarshalling
func (id *OidcClaims) UnmarshalJSON(data []byte) error {
	// unmarshal audience claim separately to account for []string, https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	type Alias OidcClaims
	aux := &struct {
		Audience any `json:"aud"`
		*Alias
	}{
		Alias: (*Alias)(id),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	switch t := aux.Audience.(type) {
	case string:
		id.Audience = t
	case []any:
		audList := []string{}
		for _, v := range t {
			audList = append(audList, v.(string))
		}
		id.Audience = strings.Join(audList, ",")
	default:
		id.Audience = ""
	}

	return nil
}

// SplitCompact splits a JWT and returns its three parts
// separately: protected headers, payload and signature.
// This is copied from github.com/lestrrat-go/jwx/v2/jws.SplitCompact
// We include it here so so that jwx is not a dependency of simpleJws
func SplitCompact(src []byte) ([]byte, []byte, []byte, error) {
	parts := bytes.Split(src, []byte("."))
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf(`invalid number of segments`)
	}
	return parts[0], parts[1], parts[2], nil
}

func ParseJWTSegment(segment []byte, v any) error {
	segmentJSON, err := util.Base64DecodeForJWT(segment)
	if err != nil {
		return fmt.Errorf("error decoding segment: %w", err)
	}

	err = json.Unmarshal(segmentJSON, v)
	if err != nil {
		return fmt.Errorf("error parsing segment: %w", err)
	}

	return nil
}
