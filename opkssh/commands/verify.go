// Copyright 2025 OpenPubkey
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

package commands

import (
	"context"

	"github.com/openpubkey/openpubkey/opkssh/policy"
	"github.com/openpubkey/openpubkey/opkssh/sshcert"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"golang.org/x/crypto/ssh"
)

// AuthFunc returns nil if the supplied PK token is permitted to login as
// username. Otherwise, an error is returned indicating the reason for rejection
type AuthFunc func(username string, pkt *pktoken.PKToken) error

// VerifyCmd provides functionality to verify OPK tokens contained in SSH
// certificates and authorize requests to SSH as a specific username using a
// configurable authorization system. It is designed to be used in conjunction
// with sshd's AuthorizedKeysCommand feature.
type VerifyCmd struct {
	// OPConfig returns configuration values used to verify the PK token
	// contained in the SSH certificate
	OPConfig providers.Config
	// Auth determines whether the verified PK token is permitted to SSH as a
	// specific user
	Auth AuthFunc
}

// Verify verifies the OPK PK token contained in the base64-encoded SSH pubkey;
// the pubkey is expected to be an SSH certificate. pubkeyType is used to
// determine how to parse the pubkey as one of the SSH certificate types.
//
// After verifying the PK token with the OP (OpenID provider), v.Auth is used to
// check if the supplied username is permitted.
//
// If all steps of verification succeed, then the expected authorized_keys file
// format string is returned (i.e. the expected line to produce on standard
// output when using sshd's AuthorizedKeysCommand feature). Otherwise, a non-nil
// error is returned.
func (v *VerifyCmd) Verify(ctx context.Context, username string, pubkey string, pubkeyType string) (string, error) {
	// Parse the b64 pubkey and expect it to be an ssh certificate
	cert, err := sshcert.NewFromAuthorizedKey(pubkeyType, pubkey)
	if err != nil {
		return "", err
	}
	if pkt, err := cert.VerifySshPktCert(ctx, v.OPConfig); err != nil { // Verify the PKT contained in the cert
		return "", err
	} else if err := v.Auth(username, pkt); err != nil { // Check if username is authorized
		return "", err
	} else { // Success!
		// sshd expects the public key in the cert, not the cert itself. This
		// public key is key of the CA the signs the cert, in our setting there
		// is no CA.
		pubkeyBytes := ssh.MarshalAuthorizedKey(cert.SshCert.SignatureKey)
		return "cert-authority " + string(pubkeyBytes), nil
	}
}

// OpkPolicyEnforcerAsAuthFunc returns an opkssh policy.Enforcer that can be
// used in the opkssh verify command.
func OpkPolicyEnforcerAsAuthFunc(username string) AuthFunc {
	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &policy.MultiFileLoader{
			FileLoader: policy.NewFileLoader(),
			Username:   username,
		},
	}
	return policyEnforcer.CheckPolicy
}
