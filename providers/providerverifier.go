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

package providers

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/jwsig"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
)

const AudPrefixForGQCommitment = "OPENPUBKEY-PKTOKEN:"

type DefaultProviderVerifier struct {
	issuer     string
	commitType CommitType
	options    ProviderVerifierOpts
}

type ProviderVerifierOpts struct {
	// If ClientID is specified, then verification will require that the ClientID
	// be present in the audience ("aud") claim of the PK token payload
	ClientID string
	// Describes the place where the cicHash is committed to in the the ID token.
	// For instance the nonce payload claim name where the cicHash was stored during issuance
	CommitType CommitType
	// Specifies whether to skip the Client ID check, defaults to false
	SkipClientIDCheck bool
	// Custom function for discovering public key of Provider
	DiscoverPublicKey *discover.PublicKeyFinder
	// Allows for successful verification of expired tokens
	SkipExpirationCheck bool
	// Only allows GQ signatures, a provider signature under any other algorithm
	// is seen as an error
	GQOnly bool
}

// Creates a new ProviderVerifier with required fields
//
// issuer: Is the OpenID provider issuer as seen in ID token e.g. "https://accounts.google.com"
// commitmentClaim: the ID token payload claim name where the cicHash was stored during issuance
func NewProviderVerifier(issuer string, options ProviderVerifierOpts) *DefaultProviderVerifier {
	v := &DefaultProviderVerifier{
		issuer:     issuer,
		commitType: options.CommitType,
		options:    options,
	}

	// If no custom DiscoverPublicKey function is set, set default
	if v.options.DiscoverPublicKey == nil {
		v.options.DiscoverPublicKey = discover.DefaultPubkeyFinder()
	}

	return v
}

func (v *DefaultProviderVerifier) Issuer() string {
	return v.issuer
}

func (v *DefaultProviderVerifier) VerifyIDToken(ctx context.Context, idToken []byte, cic *clientinstance.Claims) error {
	// Sanity check that if GQCommitment is enabled then the other options
	// are set correctly for doing GQ commitment verification. The intention is
	// to catch misconfigurations early and provide meaningful error messages.
	if v.options.CommitType.GQCommitment {
		if !v.options.GQOnly {
			return fmt.Errorf("GQCommitment requires that GQOnly is true, but GQOnly is (%t)", v.options.GQOnly)
		}
		if v.commitType.Claim != "" {
			return fmt.Errorf("GQCommitment requires that commitmentClaim is empty but commitmentClaim is (%s)", v.commitType.Claim)
		}
		if !v.options.SkipClientIDCheck {
			// When we bind the commitment to the ID Token using GQ Signatures,
			// We require that the audience is prefixed with
			// "OPENPUBKEY-PKTOKEN:". Thus, the audience can't be the client-id
			// If you are hitting this error of set SkipClientIDCheck to true
			return fmt.Errorf("GQCommitment requires that audience (aud) is not set to client-id")
		}
	}

	idt, err := jwsig.NewJwt(idToken)
	if err != nil {
		return err
	}

	// Check whether Audience claim matches provided Client ID
	// No error is thrown if option is set to skip client ID check
	if err := verifyAudience(idt, v.options.ClientID); err != nil && !v.options.SkipClientIDCheck {
		return err
	}

	algStr := idt.GetSignature().GetProtectedClaims().Alg
	if algStr == "" {
		return fmt.Errorf("provider algorithm type missing")
	}
	alg := jwa.SignatureAlgorithm(algStr)
	if alg != gq.GQ256 && v.options.GQOnly {
		return fmt.Errorf("non-GQ signatures are not supported")
	}

	switch alg {
	case gq.GQ256:
		if err := v.verifyGQSig(ctx, idt); err != nil {
			return fmt.Errorf("error verifying OP GQ signature on PK Token: %w", err)
		}
	case jwa.RS256:
		pubKeyRecord, err := v.providerPublicKey(ctx, idToken)
		if err != nil {
			return fmt.Errorf("failed to get OP public key: %w", err)
		}

		// Ensure that the algorithm of public key from OpenID Provider matches the algorithm specified in the ID Token
		_, ok := pubKeyRecord.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not an RSA public key")
		}

		if _, err := jws.Verify(idToken, jws.WithKey(alg, pubKeyRecord.PublicKey)); err != nil {
			return err
		}
	}

	if err := v.verifyCommitment(idt, cic); err != nil {
		return err
	}

	return nil
}

// This function takes in an OIDC Provider created ID token or GQ-signed modification of one and returns
// the associated public key
func (v *DefaultProviderVerifier) providerPublicKey(ctx context.Context, idToken []byte) (*discover.PublicKeyRecord, error) {
	return v.options.DiscoverPublicKey.ByToken(ctx, v.Issuer(), idToken)
}

func (v *DefaultProviderVerifier) verifyCommitment(idt *jwsig.Jwt, cic *clientinstance.Claims) error {
	var claims map[string]any
	payload, err := util.Base64DecodeForJWT([]byte(idt.GetPayload()))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return err
	}

	expectedCommitment, err := cic.Hash()
	if err != nil {
		return err
	}

	var commitment any
	var commitmentFound bool
	if v.options.CommitType.GQCommitment {
		aud, ok := claims["aud"]
		if !ok {
			return fmt.Errorf("require audience claim prefix missing in PK Token's GQCommitment")
		}

		// To prevent attacks where a attacker takes someone else's ID Token
		// and turns it into a PK Token using a GQCommitment, we require that
		// all GQ commitments explicitly signal they want to be used as
		// PK Tokens. To signal this, they prefix the audience (aud)
		// claim with the string "OPENPUBKEY-PKTOKEN:".
		// We reject all GQ commitment PK Tokens that don't have this prefix
		// in the aud claim.
		if _, ok := strings.CutPrefix(aud.(string), AudPrefixForGQCommitment); !ok {
			return fmt.Errorf("audience claim in PK Token's GQCommitment must be prefixed by (%s), got (%s) instead",
				AudPrefixForGQCommitment, aud.(string))
		}

		// Get the commitment from the GQ signed protected header claim "cic" in the ID Token
		commitment = idt.GetSignature().GetProtectedClaims().CIC
		if commitment == "" {
			return fmt.Errorf("missing GQ commitment")
		}
	} else {
		if v.commitType.Claim == "" {
			return fmt.Errorf("verifier configured with empty commitment claim")
		}

		commitment, commitmentFound = claims[v.commitType.Claim]
		if !commitmentFound {
			return fmt.Errorf("missing commitment claim %s", v.commitType.Claim)
		}
	}

	if commitment != string(expectedCommitment) {
		return fmt.Errorf("commitment claim doesn't match, got %q, expected %s", commitment, string(expectedCommitment))
	}
	return nil
}

// verifyGQSig verifies the signature of a PK token with a GQ signature. The
// parameter issuer should be the issuer of the ProviderVerifier not the
// issuer of the PK Token
func (v *DefaultProviderVerifier) verifyGQSig(ctx context.Context, idt *jwsig.Jwt) error {
	algStr := idt.GetSignature().GetProtectedClaims().Alg
	if algStr == "" {
		return fmt.Errorf("missing provider algorithm header")
	}
	if algStr != gq.GQ256.String() {
		return fmt.Errorf("signature is not of type GQ")
	}

	origHeaders, err := originalTokenHeaders(idt.GetRaw())
	if err != nil {
		return fmt.Errorf("malformed ID Token headers: %w", err)
	}

	origAlg := origHeaders.Algorithm()
	if origAlg != jwa.RS256 {
		return fmt.Errorf("expected original headers to contain RS256 alg, got %s", origAlg)
	}

	if idt.GetClaims().Issuer == "" {
		return fmt.Errorf("missing issuer in payload: %s", idt.GetPayload())
	}
	if idt.GetClaims().Issuer != v.issuer {
		return fmt.Errorf("issuer of ID Token (%s) doesn't match expected issuer (%s)", idt.GetClaims().Issuer, v.issuer)
	}

	publicKeyRecord, err := v.options.DiscoverPublicKey.ByToken(ctx, v.Issuer(), idt.GetRaw())
	if err != nil {
		return fmt.Errorf("failed to get provider public key: %w", err)
	}

	rsaKey, ok := publicKeyRecord.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("jwk is not an RSA key")
	}
	ok, err = gq.GQ256VerifyJWT(rsaKey, idt.GetRaw())
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("error verifying OP GQ signature on PK Token (ID Token invalid)")
	}
	return nil
}

func originalTokenHeaders(token []byte) (jws.Headers, error) {
	origHeadersB64, err := gq.OriginalJWTHeaders(token)
	if err != nil {
		return nil, fmt.Errorf("malformatted PK token headers: %w", err)
	}

	origHeaders, err := util.Base64DecodeForJWT(origHeadersB64)
	if err != nil {
		return nil, fmt.Errorf("error decoding original token headers: %w", err)
	}

	headers := jws.NewHeaders()
	err = json.Unmarshal(origHeaders, &headers)
	if err != nil {
		return nil, fmt.Errorf("error parsing segment: %w", err)
	}

	return headers, nil
}

func verifyAudience(idt *jwsig.Jwt, clientID string) error {
	if idt.GetClaims().Audience == "" {
		return fmt.Errorf("missing audience claim")
	}

	for _, audience := range strings.Split(idt.GetClaims().Audience, ",") {
		if audience == clientID {
			return nil
		}
	}
	return fmt.Errorf("audience does not contain clientID %s, aud = %v", clientID, idt.GetClaims().Audience)
}
