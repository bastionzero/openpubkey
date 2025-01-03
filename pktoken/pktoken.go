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

package pktoken

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/openpubkey/openpubkey/jwsig"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"

	_ "golang.org/x/crypto/sha3"
)

type SignatureType string

const (
	OIDC SignatureType = "JWT"
	CIC  SignatureType = "CIC"
	COS  SignatureType = "COS"
)

type Signature = jws.Signature

type PKToken struct {
	raw []byte // the original, raw representation of the object

	Payload []byte     // decoded payload
	Op      *Signature // Provider Signature
	Cic     *Signature // Client Signature
	Cos     *Signature // Cosigner Signature

	// We keep the tokens around as  unmarshalled values can no longer be verified
	OpToken  []byte // Base64 encoded ID Token signed by the OP
	CicToken []byte // Base64 encoded Token signed by the Client
	CosToken []byte // Base64 encoded Token signed by the Cosigner

	// FreshIDToken is the refreshed ID Token. It has a different payload from
	// other tokens and must be handled separately.
	// It is only used for POP Authentication
	FreshIDToken []byte // Base64 encoded Refreshed ID Token
}

// New creates a new PKToken from an ID Token and a CIC Token.
// It adds signatures for both tokens to the PK Token and returns the PK Token.
func New(idToken []byte, cicToken []byte) (*PKToken, error) {
	pkt := &PKToken{}

	if err := pkt.AddSignature(idToken, OIDC); err != nil {
		return nil, err
	}

	if err := pkt.AddSignature(cicToken, CIC); err != nil {
		return nil, err
	}

	return pkt, nil
}

// NewFromCompact creates a PK Token from a compact representation
func NewFromCompact(pktCom []byte) (*PKToken, error) {
	tokens, freshIDToken, err := SplitCompactPKToken(pktCom)
	if err != nil {
		return nil, err
	}
	pkt := &PKToken{}

	for _, token := range tokens {
		parsedToken, err := jwsig.NewJwt(token)
		if err != nil {
			return nil, err
		}
		typ := parsedToken.GetSignature().GetProtectedClaims().Type
		if typ == "" {
			// missing typ claim, assuming this is from the OIDC provider and set typ=OIDC=JWT
			// Okta is known not to set the typ parameter on their ID Tokens
			// The JWT RFC-7519 encourages but does not require that typ be set saying about typ
			//  "This parameter is ignored by JWT implementations; any processing of this parameter is
			// performed by the JWT application.  If present, it is RECOMMENDED that its value be "JWT"
			//  to indicate that this object is a JWT."
			//  https://datatracker.ietf.org/doc/html/rfc7519#section-5.1
			typ = string(OIDC)
		}

		sigType := SignatureType(typ)
		if err := pkt.AddSignature(token, sigType); err != nil {
			return nil, err
		}
	}
	pkt.FreshIDToken = freshIDToken
	return pkt, nil
}

// Issuer returns the issuer of the ID Token in the PKToken.
// It extracts the issuer from the PKToken payload and returns it as a string.
func (p *PKToken) Issuer() (string, error) {
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(p.Payload, &claims); err != nil {
		return "", fmt.Errorf("malformatted PK token claims: %w", err)
	}
	return claims.Issuer, nil
}

// Signs PK Token and then returns only the payload, header and signature as a JWT
func (p *PKToken) SignToken(
	signer crypto.Signer,
	alg jwa.KeyAlgorithm,
	protected map[string]any,
) ([]byte, error) {
	headers := jws.NewHeaders()
	for key, val := range protected {
		if err := headers.Set(key, val); err != nil {
			return nil, fmt.Errorf("malformatted headers: %w", err)
		}
	}
	return jws.Sign(
		p.Payload,
		jws.WithKey(
			alg,
			signer,
			jws.WithProtectedHeaders(headers),
		),
	)
}

// AddSignature will add a signature to the PKToken with the specified signature type.
// It takes a token byte slice and a signature type as input, and returns an error if the signature cannot be added.
//
// To use AddSignature, first parse the token byte slice using the jws.Parse function to obtain a jws.Message object.
// You can then extract the signature from the message object using the Signatures method, and pass it to AddSignature along with the desired signature type.
//
// The function supports three signature types: OIDC, CIC, and COS.
// These signature types correspond to the JWTs in the PK Token.
// Depending on the signature type, the function will set the corresponding field in the PKToken struct (Op, Cic, or Cos) to the provided signature.
// It will also set the corresponding token field (OpToken, CicToken, or CosToken) to the provided token byte slice.
//
// If the signature type is not recognized, an error will be returned.
func (p *PKToken) AddSignature(token []byte, sigType SignatureType) error {
	message, err := jws.Parse(token)
	if err != nil {
		return err
	}

	// If there is no payload, we set the provided token's payload as current, otherwise
	// we make sure that the new payload matches current
	if p.Payload == nil {
		p.Payload = message.Payload()
	} else if !bytes.Equal(p.Payload, message.Payload()) {
		return fmt.Errorf("payload in the GQ token (%s) does not match the existing payload in the PK Token (%s)", p.Payload, message.Payload())
	}

	signature := message.Signatures()[0]

	if sigType == CIC || sigType == COS {
		protected := signature.ProtectedHeaders()
		if sigTypeFound, ok := protected.Get(jws.TypeKey); !ok {
			return fmt.Errorf("required 'typ' claim not found in protected")
		} else if sigTypeFoundStr, ok := sigTypeFound.(string); !ok {
			return fmt.Errorf("'typ' claim in protected must be a string but was a %T", sigTypeFound)
		} else if sigTypeFoundStr != string(sigType) {
			return fmt.Errorf("incorrect 'typ' claim in protected, expected (%s), got (%s)", sigType, sigTypeFound)
		}
	}

	switch sigType {
	case OIDC:
		p.Op = signature
		p.OpToken = token
	case CIC:
		p.Cic = signature
		p.CicToken = token
	case COS:
		p.Cos = signature
		p.CosToken = token
	default:
		return fmt.Errorf("unrecognized signature type: %s", string(sigType))
	}
	return nil
}

func (p *PKToken) ProviderAlgorithm() (jwa.SignatureAlgorithm, bool) {
	alg, ok := p.Op.ProtectedHeaders().Get(jws.AlgorithmKey)
	if !ok {
		return "", false
	}

	return alg.(jwa.SignatureAlgorithm), true
}

func (p *PKToken) GetCicValues() (*clientinstance.Claims, error) {
	cicPH, err := p.Cic.ProtectedHeaders().AsMap(context.TODO())
	if err != nil {
		return nil, err
	}

	return clientinstance.ParseClaims(cicPH)
}

func (p *PKToken) Hash() (string, error) {
	/*
		We set the raw variable when unmarshalling from json (the only current string representation of a
		PK Token) so when we hash we use the same representation that was given for consistency. When the
		token being hashed is a new PK Token, we marshal it ourselves. This can introduce some issues based
		on how different languages format their json strings.
	*/
	message := p.raw
	var err error
	if message == nil {
		message, err = json.Marshal(p)
		if err != nil {
			return "", err
		}
	}

	hash := util.B64SHA3_256(message)
	return string(hash), nil
}

// Compact serializes a PK Token into a compact representation.
func (p *PKToken) Compact() ([]byte, error) {
	tokens := [][]byte{}
	if p.OpToken != nil {
		tokens = append(tokens, p.OpToken)
	}
	if p.CicToken != nil {
		tokens = append(tokens, p.CicToken)
	}
	if p.CosToken != nil {
		tokens = append(tokens, p.CosToken)
	}
	return CompactPKToken(tokens, p.FreshIDToken)
}

func (p *PKToken) MarshalJSON() ([]byte, error) {
	rawJws := jwsig.Jws{
		Payload:    string(util.Base64EncodeForJWT(p.Payload)),
		Signatures: []jwsig.Signature{},
	}
	var opPublicHeader map[string]any
	var err error
	if p.Op.PublicHeaders() != nil {
		if opPublicHeader, err = p.Op.PublicHeaders().AsMap(context.Background()); err != nil {
			return nil, err
		}
	}
	if err = rawJws.AddSignature(p.OpToken, jwsig.WithPublicHeader(opPublicHeader)); err != nil {
		return nil, err
	}
	if err = rawJws.AddSignature(p.CicToken); err != nil {
		return nil, err
	}
	if p.CosToken != nil {
		if err = rawJws.AddSignature(p.CosToken); err != nil {
			return nil, err
		}
	}
	return json.Marshal(rawJws)
}

func (p *PKToken) UnmarshalJSON(data []byte) error {
	var rawJws jwsig.Jws
	if err := json.Unmarshal(data, &rawJws); err != nil {
		return err
	}
	var parsed jws.Message
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}

	p.Payload = parsed.Payload() // base64 decoded

	opCount := 0
	cicCount := 0
	cosCount := 0
	for i, signature := range parsed.Signatures() {
		// for some reason the unmarshaled signatures have empty non-nil
		// public headers. set them to nil instead.
		public := signature.PublicHeaders()
		pubMap, _ := public.AsMap(context.Background())
		if len(pubMap) == 0 {
			signature.SetPublicHeaders(nil)
		}

		protected := signature.ProtectedHeaders()
		var sigType SignatureType

		typeHeader, ok := protected.Get(jws.TypeKey)
		if ok {
			sigTypeStr, ok := typeHeader.(string)
			if !ok {
				return fmt.Errorf(`provided "%s" is of wrong type, expected string`, jws.TypeKey)
			}

			sigType = SignatureType(sigTypeStr)
		} else {
			// missing typ claim, assuming this is from the OIDC provider
			sigType = OIDC
		}

		switch sigType {
		case OIDC:
			opCount += 1
			p.Op = signature
			p.OpToken = []byte(rawJws.Signatures[i].Protected + "." + rawJws.Payload + "." + rawJws.Signatures[i].Signature)
		case CIC:
			cicCount += 1
			p.Cic = signature
			p.CicToken = []byte(rawJws.Signatures[i].Protected + "." + rawJws.Payload + "." + rawJws.Signatures[i].Signature)
		case COS:
			cosCount += 1
			p.Cos = signature
			p.CosToken = []byte(rawJws.Signatures[i].Protected + "." + rawJws.Payload + "." + rawJws.Signatures[i].Signature)
		default:
			return fmt.Errorf("unrecognized signature type: %s", sigType)
		}
	}

	// Do some signature count verifications
	if opCount == 0 {
		return fmt.Errorf(`at least one signature of type "oidc" or "oidc_gq" is required`)
	} else if opCount > 1 {
		return fmt.Errorf(`only one signature of type "oidc" or "oidc_gq" is allowed, found %d`, opCount)
	}

	if cicCount == 0 {
		return fmt.Errorf(`at least one signature of type "cic" is required`)
	} else if cicCount > 1 {
		return fmt.Errorf(`only one signature of type "cic" is allowed, found %d`, cicCount)
	}

	if cosCount > 1 {
		return fmt.Errorf(`only one signature of type "cos" is allowed, found %d`, cosCount)
	}

	return nil
}

// DeepCopy creates a complete and independent copy of this PKToken,
func (p *PKToken) DeepCopy() (*PKToken, error) {
	pktJson, err := p.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var pktCopy PKToken
	if err := json.Unmarshal(pktJson, &pktCopy); err != nil {
		return nil, err
	}
	pktCopy.FreshIDToken = p.FreshIDToken
	return &pktCopy, nil
}
