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

package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/openpubkey/openpubkey/jwsig"
	"github.com/openpubkey/openpubkey/pktoken"
)

// CreateX509Cert generates a self-signed x509 cert from a PK token
//   - OP 'sub' claim is mapped to the CN and SANs fields
//   - User public key is mapped to the RawSubjectPublicKeyInfo field
//   - Raw PK token is mapped to the SubjectKeyId field
func CreateX509Cert(pkToken *pktoken.PKToken, signer crypto.Signer) ([]byte, error) {
	template, err := PktToX509Template(pkToken)
	if err != nil {
		return nil, fmt.Errorf("error creating X.509 template: %w", err)
	}

	// create a self-signed X.509 certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("error creating X.509 certificate: %w", err)
	}
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return pem.EncodeToMemory(certBlock), nil
}

// PktToX509Template takes a PK Token and returns a X.509 certificate template
// with the fields of the template set to the values in the X509
func PktToX509Template(pkt *pktoken.PKToken) (*x509.Certificate, error) {
	pktJson, err := json.Marshal(pkt)
	if err != nil {
		return nil, fmt.Errorf("error marshalling PK token to JSON: %w", err)
	}

	// get subject identifier from pk token
	idtClaims := new(jwsig.OidcClaims)
	if err := json.Unmarshal(pkt.Payload, idtClaims); err != nil {
		return nil, err
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

	// encode ephemeral public key
	ecPub, err := x509.MarshalPKIXPublicKey(rawkey)
	if err != nil {
		return nil, fmt.Errorf("error marshalling public key: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:            big.NewInt(1),
		Subject:                 pkix.Name{CommonName: idtClaims.Subject},
		RawSubjectPublicKeyInfo: ecPub,
		NotBefore:               time.Now(),
		NotAfter:                time.Now().Add(365 * 24 * time.Hour), // valid for 1 year
		KeyUsage:                x509.KeyUsageDigitalSignature,
		ExtKeyUsage:             []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid:   true,
		DNSNames:                []string{idtClaims.Subject},
		IsCA:                    false,
		ExtraExtensions: []pkix.Extension{{
			// OID for OIDC Issuer extension
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
			Critical: false,
			Value:    []byte(idtClaims.Issuer),
		}},
		SubjectKeyId: pktJson,
	}

	return template, nil
}
