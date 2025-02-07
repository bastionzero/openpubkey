package policy_test

import (
	"testing"

	"github.com/bastionzero/opk-ssh/policy"
	"github.com/stretchr/testify/assert"
)

func TestAddAllowedPrincipal(t *testing.T) {
	t.Parallel()

	// Test adding an allowed principal to an opk-ssh policy
	tests := []struct {
		name           string
		principal      string
		userEmail      string
		initialPolicy  *policy.Policy
		expectedPolicy *policy.Policy
	}{
		{
			name:          "empty policy",
			principal:     "test",
			userEmail:     "alice@example.com",
			initialPolicy: &policy.Policy{},
			expectedPolicy: &policy.Policy{
				Users: []policy.User{
					{
						Email:      "alice@example.com",
						Principals: []string{"test"},
					},
				},
			},
		},
		{
			name:      "non-empty policy. user not found",
			principal: "test",
			userEmail: "bob@example.com",
			initialPolicy: &policy.Policy{
				Users: []policy.User{
					{
						Email:      "alice@example.com",
						Principals: []string{"test", "test2"},
					},
				}},
			expectedPolicy: &policy.Policy{
				Users: []policy.User{
					{
						Email:      "bob@example.com",
						Principals: []string{"test"},
					},
					{
						Email:      "alice@example.com",
						Principals: []string{"test", "test2"},
					},
				},
			},
		},
		{
			name:      "user already exists. new principal",
			principal: "test3",
			userEmail: "alice@example.com",
			initialPolicy: &policy.Policy{
				Users: []policy.User{
					{
						Email:      "alice@example.com",
						Principals: []string{"test", "test2"},
					},
				}},
			expectedPolicy: &policy.Policy{
				Users: []policy.User{
					{
						Email:      "alice@example.com",
						Principals: []string{"test", "test2", "test3"},
					},
				},
			},
		},
		{
			name:      "user already exists. principal not new.",
			principal: "test",
			userEmail: "alice@example.com",
			initialPolicy: &policy.Policy{
				Users: []policy.User{
					{
						Email:      "alice@example.com",
						Principals: []string{"test"},
					},
				}},
			expectedPolicy: &policy.Policy{
				Users: []policy.User{
					{
						Email:      "alice@example.com",
						Principals: []string{"test"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("AddAllowedPrincipal(principal=%s, userEmail=%s)", tt.principal, tt.userEmail)
			t.Logf("Initial policy: %#v", tt.initialPolicy)
			tt.initialPolicy.AddAllowedPrincipal(tt.principal, tt.userEmail)
			assert.ElementsMatch(t, tt.expectedPolicy.Users, tt.initialPolicy.Users)
		})
	}
}
