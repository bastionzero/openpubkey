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

package gitlab_example

import (
	"testing"

	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/stretchr/testify/require"
)

func TestGitlabExample(t *testing.T) {
	opOpts := mocks.MockProviderOpts{
		Issuer:       "mockIssuer",
		ClientID:     "mockClient-ID",
		SignGQ:       true,
		GQCommitment: true,
		VerifierOpts: providers.ProviderVerifierOpts{
			SkipClientIDCheck: true,
			GQOnly:            true,
			GQCommitment:      true,
		},
	}
	op, _, _, err := mocks.NewMockProvider(opOpts)
	require.NoError(t, err)

	opts := Opts{
		altOp: op,
	}

	err = SignWithGitlab(opts)
	require.NoError(t, err)
}
