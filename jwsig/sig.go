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
	"encoding/json"

	"github.com/openpubkey/openpubkey/util"
)

type Signature struct {
	Protected       string                 `json:"protected"` // Base64 encoded
	protectedClaims *ProtectedClaims       // Unmarshalled protected claims
	Public          map[string]interface{} `json:"header,omitempty"`
	Signature       string                 `json:"signature"` // Base64 encoded
}

type ProtectedClaims struct {
	Alg   string `json:"alg"`
	Jkt   string `json:"jkt,omitempty"`
	KeyID string `json:"kid,omitempty"`
	Type  string `json:"typ,omitempty"`
	CIC   string `json:"cic,omitempty"`
}

func (s *Signature) GetTyp() (string, error) {
	decodedProtected, err := util.Base64DecodeForJWT([]byte(s.Protected))
	if err != nil {
		return "", err
	}
	type protectedTyp struct {
		Typ string `json:"typ"`
	}
	var ph protectedTyp
	err = json.Unmarshal(decodedProtected, &ph)
	if err != nil {
		return "", err
	}
	return ph.Typ, nil
}

func (s *Signature) GetProtectedClaims() *ProtectedClaims {
	return s.protectedClaims
}
