package policy_test

import (
	"path"
	"strings"
	"testing"

	"github.com/bastionzero/opk-ssh/policy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func policyToMapUsers(p *policy.Policy) map[string]policy.User {
	m := make(map[string]*policy.User)
	for e, user := range p.Users {
		if seenUserEntry, ok := m[user.Email]; ok {
			seenUserEntry.Principals = append(seenUserEntry.Principals, user.Principals...)
		} else {
			entry := p.Users[e]
			m[user.Email] = &entry
		}
	}

	mapWithValues := make(map[string]policy.User)
	for k, v := range m {
		// Safe because we never put nil in map above
		mapWithValues[k] = *v
	}
	return mapWithValues
}

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// rootPolicy is the policy read from the system default policy path. If
		// nil the file will be missing
		rootPolicy *policy.Policy
		// userPolicy is the policy read from the ValidUser's home directory. If
		// nil the file will be missing
		userPolicy    *policy.Policy
		expectedUsers map[string]policy.User
		shouldError   bool
	}{
		{
			name:        "both policies are missing",
			rootPolicy:  nil,
			userPolicy:  nil,
			shouldError: true,
		},
		{
			name: "only root policy exists",
			rootPolicy: &policy.Policy{
				Users: []policy.User{
					{
						Email:      "alice@example.com",
						Principals: []string{"test"},
					},
				},
			},
			expectedUsers: map[string]policy.User{
				"alice@example.com": {Email: "alice@example.com", Principals: []string{"test"}},
			},
		},
		{
			name: "only user policy exists",
			userPolicy: &policy.Policy{
				Users: []policy.User{
					{
						Email:      "alice@example.com",
						Principals: []string{ValidUser.Username, "bob"},
					},
				},
			},
			expectedUsers: map[string]policy.User{
				"alice@example.com": {Email: "alice@example.com", Principals: []string{ValidUser.Username}},
			},
		},
		{
			name: "both user and root policy exist",
			rootPolicy: &policy.Policy{
				Users: []policy.User{
					{
						Email:      "alice@example.com",
						Principals: []string{"test"},
					},
					{
						Email:      "charlie@example.com",
						Principals: []string{"test"},
					},
				},
			},
			userPolicy: &policy.Policy{
				Users: []policy.User{
					{
						Email:      "alice@example.com",
						Principals: []string{ValidUser.Username},
					},
					{
						Email:      "bob@example.com",
						Principals: []string{ValidUser.Username},
					},
				},
			},
			expectedUsers: map[string]policy.User{
				"alice@example.com":   {Email: "alice@example.com", Principals: []string{"test", ValidUser.Username}},
				"bob@example.com":     {Email: "bob@example.com", Principals: []string{ValidUser.Username}},
				"charlie@example.com": {Email: "charlie@example.com", Principals: []string{"test"}},
			},
		},
		{
			name: "both user and root policy exist but no valid user policy entries",
			rootPolicy: &policy.Policy{
				Users: []policy.User{
					{
						Email:      "alice@example.com",
						Principals: []string{"test"},
					},
					{
						Email:      "charlie@example.com",
						Principals: []string{"test"},
					},
				},
			},
			userPolicy: &policy.Policy{
				Users: []policy.User{
					{
						Email:      "alice@example.com",
						Principals: []string{"test"},
					},
					{
						Email:      "bob@example.com",
						Principals: []string{"test", "test2"},
					},
					{
						Email:      "charlie@example.com",
						Principals: []string{"test", "test2", "test3"},
					},
				},
			},
			expectedUsers: map[string]policy.User{
				"alice@example.com":   {Email: "alice@example.com", Principals: []string{"test"}},
				"charlie@example.com": {Email: "charlie@example.com", Principals: []string{"test"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Init SUT on each sub-test
			multiFileLoader := &policy.MultiFileLoader{
				FileLoader: NewTestPolicyFileLoader(afero.NewMemMapFs(), &MockUserLookup{User: ValidUser}),
				Username:   ValidUser.Username,
			}
			mockFs := multiFileLoader.Fs

			t.Logf("Root policy: %#v", tt.rootPolicy)
			t.Logf("User policy: %#v", tt.userPolicy)

			// Create files at expected paths
			expectedPaths := []string{}
			if tt.rootPolicy != nil {
				policyYaml, err := tt.rootPolicy.ToYAML()
				require.NoError(t, err)
				afero.WriteFile(mockFs, policy.SystemDefaultPolicyPath, policyYaml, 0600)
				expectedPaths = append(expectedPaths, policy.SystemDefaultPolicyPath)
			}
			if tt.userPolicy != nil {
				policyYaml, err := tt.userPolicy.ToYAML()
				require.NoError(t, err)
				expectedPath := path.Join(ValidUser.HomeDir, ".opk", "policy.yml")
				afero.WriteFile(mockFs, expectedPath, policyYaml, 0600)
				expectedPaths = append(expectedPaths, expectedPath)
			}

			policy, source, err := multiFileLoader.Load()

			if tt.shouldError {
				require.Error(t, err)
				require.Nil(t, policy, "should not return policy if error")
				require.Empty(t, source.Source(), "should not return source if error")
			} else {
				// Check error
				require.NoError(t, err)

				// Check paths
				paths := strings.Split(source.Source(), ",")
				var pathsCleaned []string
				for _, p := range paths {
					pathsCleaned = append(pathsCleaned, strings.TrimSpace(p))
				}
				require.ElementsMatch(t, expectedPaths, pathsCleaned)

				// Check user entries
				gotUsers := policyToMapUsers(policy)
				for email, expectedEntry := range tt.expectedUsers {
					gotEntry, ok := gotUsers[email]
					if assert.True(t, ok, "policy should have entry for email %s", email) {
						assert.Equal(t, expectedEntry.Email, gotEntry.Email)
						assert.ElementsMatch(t, expectedEntry.Principals, gotEntry.Principals)
					}
				}
			}
		})
	}
}
