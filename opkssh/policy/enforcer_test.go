package policy_test

import (
	"context"
	"testing"

	"github.com/bastionzero/opk-ssh/policy"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

var policyTest = &policy.Policy{
	Users: []policy.User{
		{
			Email:      "alice@bastionzero.com",
			Principals: []string{"test"},
		},
		{
			Email:      "arthur.aardvark@example.com",
			Principals: []string{"test"},
		},
		{
			Email:      "bob@example.com",
			Principals: []string{"test"},
		},
	},
}

var policyTestNoEntry = &policy.Policy{
	Users: []policy.User{
		{
			Email:      "alice@bastionzero.com",
			Principals: []string{"test"},
		},
		{
			Email:      "bob@example.com",
			Principals: []string{"test"},
		},
	},
}

type MockPolicyLoader struct {
	// Policy is returned on any call to Load() if Error is nil
	Policy *policy.Policy
	// Error is returned on any call to Load() if non-nil
	Error error
}

var _ policy.Loader = &MockPolicyLoader{}

// Load implements policy.Loader.
func (m *MockPolicyLoader) Load() (*policy.Policy, policy.Source, error) {
	if m.Error == nil {
		return m.Policy, policy.EmptySource{}, nil
	} else {
		return nil, nil, m.Error
	}
}

func TestPolicyApproved(t *testing.T) {
	t.Parallel()

	alg := jwa.ES256

	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	op, err := providers.NewMockOpenIdProvider()
	require.NoError(t, err)

	client := &client.OpkClient{
		Op: op,
	}

	pkt, err := client.OidcAuth(context.Background(), signer, alg, map[string]any{}, false)
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyTest},
	}

	// Check that policy yaml is properly parsed and checked
	err = policyEnforcer.CheckPolicy("test", pkt)
	require.NoError(t, err)
}

func TestPolicyDeniedBadUser(t *testing.T) {
	t.Parallel()

	alg := jwa.ES256

	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	op, err := providers.NewMockOpenIdProvider()
	require.NoError(t, err)

	client := &client.OpkClient{
		Op: op,
	}

	pkt, err := client.OidcAuth(context.Background(), signer, alg, map[string]any{}, false)
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyTest},
	}

	err = policyEnforcer.CheckPolicy("baduser", pkt)
	require.Error(t, err, "user should not have access")
}

func TestPolicyDeniedNoUserEntry(t *testing.T) {
	t.Parallel()

	alg := jwa.ES256

	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	op, err := providers.NewMockOpenIdProvider()
	require.NoError(t, err)

	client := &client.OpkClient{
		Op: op,
	}

	pkt, err := client.OidcAuth(context.Background(), signer, alg, map[string]any{}, false)
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyTestNoEntry},
	}

	err = policyEnforcer.CheckPolicy("test", pkt)
	require.Error(t, err, "user should not have access")
}
