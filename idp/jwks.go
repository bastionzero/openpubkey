package idp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/crypto/sha3"
)

func NewJwksSet(signer crypto.Signer, alg jwa.KeyAlgorithm) ([]byte, string, error) {

	pubkey := signer.Public()
	var pubkeyBytes []byte
	var kid string

	switch key := pubkey.(type) {
	case *ecdsa.PublicKey:
		pubkeyBytes = key.X.Bytes()
		pubkeyHash := sha3.Sum256(pubkeyBytes)
		kid = hex.EncodeToString(pubkeyHash[:])
	case *rsa.PublicKey:
		pubkeyBytes = key.N.Bytes()
		pubkeyHash := sha3.Sum256(pubkeyBytes)
		kid = hex.EncodeToString(pubkeyHash[:])
	default:
		return nil, "", fmt.Errorf("unsupported key type %T", pubkey)
	}

	// Generate our JWKS using our signing key
	jwkKey, err := jwk.PublicKeyOf(signer)
	if err != nil {
		return nil, "", err
	}
	jwkKey.Set(jwk.AlgorithmKey, alg)
	jwkKey.Set(jwk.KeyIDKey, kid)

	// Put our jwk into a set
	keySet := jwk.NewSet()
	keySet.AddKey(jwkKey)

	// Now convert our key set into the raw bytes for printing later
	keySetBytes, _ := json.MarshalIndent(keySet, "", "  ")
	if err != nil {
		return nil, "", err
	}

	return keySetBytes, kid, nil
}
