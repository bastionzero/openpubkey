package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

type CosignerConfig struct {
	Alg    jwa.KeyAlgorithm
	Pubkey jwk.Key
}

func GenCAKeyPair() ([]byte, *ecdsa.PrivateKey, error) {
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Openpubkey-test-ca-cert"},
			Country:       []string{"International"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{"Anon Anon St."},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caPkSk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPkSk.PublicKey, caPkSk)
	if err != nil {
		return nil, nil, err
	}

	return caBytes, caPkSk, nil
}

func PktTox509(pktJson []byte, caBytes []byte, caPkSk *ecdsa.PrivateKey, requiredAudience string) ([]byte, error) {
	var pkt *pktoken.PKToken
	if err := json.Unmarshal(pktJson, &pkt); err != nil {
		return nil, err
	}

	err := pkt.VerifyCicSig()
	if err != nil {
		return nil, err
	}

	// TODO: verify cosigner
	// cosignerConfig := &CosignerConfig {
	// 	Alg: "ES256",
	// 	Pubkey: "TODO",
	// }
	// err = pkt.VerifyCosSig()
	// if err != nil {
	// 	return nil, err
	// }

	var payload struct {
		Issuer   string   `json:"iss"`
		Audience []string `json:"aud"`
		Email    string   `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &payload); err != nil {
		return nil, err
	}

	if payload.Audience[0] != requiredAudience {
		return nil, fmt.Errorf("audience 'aud' claim in PK Token did not match audience required by CA, it was %s instead", payload.Audience)
	}

	caTemplate, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, err
	}

	subject := payload.Email
	oidcIssuer := payload.Issuer

	// Based on template from https://github.com/sigstore/fulcio/blob/3c8fbea99c71fedfe47d39e12159286eb443a917/pkg/test/cert_utils.go#L195
	subTemplate := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		EmailAddresses: []string{subject},
		NotBefore:      time.Now().Add(-1 * time.Minute),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		IsCA:           false,
		ExtraExtensions: []pkix.Extension{{
			// OID for OIDC Issuer extension
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
			Critical: false,
			Value:    []byte(oidcIssuer),
		}},
		SubjectKeyId: []byte(util.Base64EncodeForJWT(pktJson)),
	}

	cic, err := pkt.GetCicValues()
	if err != nil {
		return nil, err
	}
	upk := cic.PublicKey()

	var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
	if err := upk.Raw(&rawkey); err != nil {
		return nil, err
	}
	pk := rawkey.(*ecdsa.PublicKey)

	subCertBytes, err := x509.CreateCertificate(rand.Reader, subTemplate, caTemplate, pk, caPkSk)
	if err != nil {
		return nil, err
	}

	subCert, err := x509.ParseCertificate(subCertBytes)
	if err != nil {
		return nil, err
	}

	var pemSubCert bytes.Buffer
	err = pem.Encode(&pemSubCert, &pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	if err != nil {
		return nil, err
	}

	return pemSubCert.Bytes(), nil
}
