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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	mathrand "math/rand"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/exp/maps"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/jwsig"
)

type MockProviderBackend struct {
	Issuer                string
	PublicKeyFinder       discover.PublicKeyFinder
	ProviderSigningKeySet map[string]crypto.Signer            // kid (keyId) -> signing key
	ProviderPublicKeySet  map[string]discover.PublicKeyRecord // kid (keyId) -> PublicKeyRecord
	IDTokensTemplate      *IDTokenTemplate
}

func NewMockProviderBackend(issuer string, numKeys int) (*MockProviderBackend, error) {
	providerSigningKeySet, providerPublicKeySet, err := CreateRS256KeySet(issuer, numKeys)
	if err != nil {
		return nil, err
	}

	return &MockProviderBackend{
		Issuer: issuer,
		PublicKeyFinder: discover.PublicKeyFinder{
			JwksFunc: func(ctx context.Context, issuer string) ([]byte, error) {
				keySet := jwk.NewSet()
				for kid, record := range providerPublicKeySet {
					jwkKey, err := jwk.PublicKeyOf(record.PublicKey)
					if err != nil {
						return nil, err
					}
					if err := jwkKey.Set(jwk.AlgorithmKey, record.Alg); err != nil {
						return nil, err
					}
					if err := jwkKey.Set(jwk.KeyIDKey, kid); err != nil {
						return nil, err
					}

					// Put our jwk into a set
					if err := keySet.AddKey(jwkKey); err != nil {
						return nil, err
					}
				}
				return json.MarshalIndent(keySet, "", "  ")
			},
		},
		ProviderSigningKeySet: providerSigningKeySet,
		ProviderPublicKeySet:  providerPublicKeySet,
	}, nil
}

func (o *MockProviderBackend) GetPublicKeyFinder() *discover.PublicKeyFinder {
	return &o.PublicKeyFinder
}

func (o *MockProviderBackend) GetProviderPublicKeySet() map[string]discover.PublicKeyRecord {
	return o.ProviderPublicKeySet
}

func (o *MockProviderBackend) GetProviderSigningKeySet() map[string]crypto.Signer {
	return o.ProviderSigningKeySet
}

func (o *MockProviderBackend) SetIDTokenTemplate(template *IDTokenTemplate) {
	o.IDTokensTemplate = template
}

func (o *MockProviderBackend) RequestTokensOverrideFunc(cicHash string) (*jwsig.Tokens, error) {
	o.IDTokensTemplate.AddCommit(cicHash)
	return o.IDTokensTemplate.IssueToken()
}

func (o *MockProviderBackend) RandomSigningKey() (crypto.Signer, string, discover.PublicKeyRecord) {
	keyIDs := maps.Keys(o.GetProviderPublicKeySet())
	keyID := keyIDs[mathrand.Intn(len(keyIDs))]
	return o.GetProviderSigningKeySet()[keyID], keyID, o.GetProviderPublicKeySet()[keyID]
}

func CreateRS256KeySet(issuer string, numKeys int) (map[string]crypto.Signer, map[string]discover.PublicKeyRecord, error) {
	return CreateKeySet(issuer, "RS256", numKeys)
}

func CreateES256KeySet(issuer string, numKeys int) (map[string]crypto.Signer, map[string]discover.PublicKeyRecord, error) {
	return CreateKeySet(issuer, "ES256", numKeys)
}

func CreateKeySet(issuer string, alg string, numKeys int) (map[string]crypto.Signer, map[string]discover.PublicKeyRecord, error) {
	providerSigningKeySet := map[string]crypto.Signer{}
	providerPublicKeySet := map[string]discover.PublicKeyRecord{}

	for i := 0; i < numKeys; i++ {
		kid := fmt.Sprintf("kid-%d", i)

		var signingKey crypto.Signer
		var err error
		switch alg {
		case "ES256":
			if signingKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
				return nil, nil, err
			}
		case "RS256":
			if signingKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, fmt.Errorf("unsupported alg: %s", alg)
		}

		providerSigningKeySet[string(kid)] = signingKey
		providerPublicKeySet[string(kid)] = discover.PublicKeyRecord{
			PublicKey: signingKey.Public(),
			Alg:       alg,
			Issuer:    issuer,
		}
	}
	return providerSigningKeySet, providerPublicKeySet, nil
}
