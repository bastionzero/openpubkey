package cosigner

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/cosigner/msgs"
	"github.com/openpubkey/openpubkey/pktoken"
)

type AuthCosigner struct {
	Cosigner
	Issuer       string
	KeyID        string
	AuthIdIter   atomic.Uint64
	HmacKey      []byte
	AuthStateMap map[string]*AuthState
	AuthCodeMap  map[string]string
}

func NewAuthCosigner(signer crypto.Signer, alg jwa.SignatureAlgorithm, issuer, keyID string) (*AuthCosigner, error) {
	hmacKey := make([]byte, 64)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, err
	}

	return &AuthCosigner{
		Cosigner: Cosigner{
			Alg:    alg,
			Signer: signer},
		Issuer:       issuer,
		KeyID:        keyID,
		AuthIdIter:   atomic.Uint64{},
		HmacKey:      hmacKey,
		AuthStateMap: make(map[string]*AuthState),
		AuthCodeMap:  make(map[string]string),
	}, nil
}

func (c *AuthCosigner) InitAuth(pkt *pktoken.PKToken, sig []byte) (string, error) {
	msg, err := pkt.VerifySignedMessage(sig)
	if err != nil {
		return "", err
	}
	var initMFAAuth *msgs.InitMFAAuth
	if err := json.Unmarshal(msg, &initMFAAuth); err != nil {
		return "", fmt.Errorf("failed to parse InitMFAAuth message: %w", err)
	} else if time.Since(time.Unix(initMFAAuth.TimeSigned, 0)).Minutes() > 2 {
		return "", fmt.Errorf("timestamp (%d) in InitMFAAuth message too old, current time is (%d)", initMFAAuth.TimeSigned, time.Now().Unix())
	} else if time.Until(time.Unix(initMFAAuth.TimeSigned, 0)).Minutes() > 2 {
		return "", fmt.Errorf("timestamp (%d) in InitMFAAuth message to far in the future, current time is (%d)", initMFAAuth.TimeSigned, time.Now().Unix())
	} else if authState, err := NewAuthState(pkt, initMFAAuth.RedirectUri, initMFAAuth.Nonce); err != nil {
		return "", err
	} else if authID, err := c.CreateAuthID(pkt); err != nil {
		return "", err
	} else {
		c.AuthStateMap[authID] = authState
		return authID, nil
	}
}

func (c *AuthCosigner) CreateAuthID(pkt *pktoken.PKToken) (string, error) {
	authIdInt := c.AuthIdIter.Add(1)
	iterAndTime := []byte{}
	iterAndTime = binary.LittleEndian.AppendUint64(iterAndTime, uint64(authIdInt))
	iterAndTime = binary.LittleEndian.AppendUint64(iterAndTime, uint64(time.Now().Unix()))
	mac := hmac.New(crypto.SHA3_256.New, c.HmacKey)
	if n, err := mac.Write(iterAndTime); err != nil {
		return "", err
	} else if n != 16 {
		return "", fmt.Errorf("unexpected number of bytes read by HMAC, expected 16, got %d", n)
	} else {
		return hex.EncodeToString(mac.Sum(nil)), nil
	}
}

func (c *AuthCosigner) NewAuthcode(authID string) (string, error) {
	authCodeBytes := make([]byte, 32)
	if _, err := rand.Read(authCodeBytes); err != nil {
		return "", err
	}
	authCode := hex.EncodeToString(authCodeBytes)
	c.AuthCodeMap[authCode] = authID
	return authCode, nil
}

func (c *AuthCosigner) RedeemAuthcode(sig []byte) ([]byte, error) {
	msg, err := jws.Parse(sig)
	if err != nil {
		return nil, err
	}
	if authID, ok := c.AuthCodeMap[string(msg.Payload())]; !ok {
		return nil, fmt.Errorf("Invalid authcode")
	} else {
		authState := c.AuthStateMap[authID]
		pkt := authState.Pkt

		_, err := authState.Pkt.VerifySignedMessage(sig)
		if err != nil {
			fmt.Println("error verifying sig:", err)
			return nil, err
		}
		return c.IssueSignature(pkt, authID)
	}
}

func (c *AuthCosigner) IssueSignature(pkt *pktoken.PKToken, authID string) ([]byte, error) {
	authState := c.AuthStateMap[authID]

	protected := pktoken.CosignerClaims{
		Iss:         c.Issuer,
		KeyID:       c.KeyID,
		Algorithm:   c.Alg.String(),
		AuthID:      authID,
		AuthTime:    time.Now().Unix(),
		IssuedAt:    time.Now().Unix(),
		Expiration:  time.Now().Add(time.Hour).Unix(),
		RedirectURI: authState.RedirectURI,
		Nonce:       authState.Nonce,
	}

	// Now that our mfa has authenticated the user, we can add our signature
	return c.Cosign(pkt, protected)
}

type AuthState struct {
	Pkt         *pktoken.PKToken
	Issuer      string // ID Token issuer (iss)
	Aud         string // ID Token audience (aud)
	Sub         string // ID Token subject ID (sub)
	Username    string // ID Token email or username
	DisplayName string // ID Token display name (or username if none given)
	RedirectURI string // Redirect URI
	Nonce       string // Nonce supplied by user
	SigIssued   bool   // Was the pkt cosigned
}

func NewAuthState(pkt *pktoken.PKToken, ruri string, nonce string) (*AuthState, error) {
	var claims struct {
		Issuer string `json:"iss"`
		Aud    any    `json:"aud"`
		Sub    string `json:"sub"`
		Email  string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PK Token: %w", err)
	}
	// An audience can be a string or an array of strings.
	//
	// RFC-7519 JSON Web Token (JWT) says:
	// "In the general case, the "aud" value is an array of case-
	// sensitive strings, each containing a StringOrURI value.  In the
	// special case when the JWT has one audience, the "aud" value MAY be a
	// single case-sensitive string containing a StringOrURI value."
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	var audience string
	switch t := claims.Aud.(type) {
	case string:
		audience = t
	case []any:
		audList := []string{}
		for _, v := range t {
			audList = append(audList, v.(string))
		}
		audience = strings.Join(audList, ",")
	default:
		return nil, fmt.Errorf("failed to deserialize aud (audience) claim in ID Token: %d", t)
	}

	return &AuthState{
		Pkt:         pkt,
		Issuer:      claims.Issuer,
		Aud:         audience,
		Sub:         claims.Sub,
		Username:    claims.Email,
		DisplayName: strings.Split(claims.Email, "@")[0], //TODO: Use full name from ID Token
		RedirectURI: ruri,
		Nonce:       nonce,
		SigIssued:   false,
	}, nil

}

type UserKey struct {
	Issuer string // ID Token issuer (iss)
	Aud    string // ID Token audience (aud)
	Sub    string // ID Token subject ID (sub)
}

func (as AuthState) UserKey() UserKey {
	return UserKey{Issuer: as.Issuer, Aud: as.Aud, Sub: as.Sub}
}