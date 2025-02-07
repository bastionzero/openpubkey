//go:build integration

package integration

import (
	"fmt"
	"io"
	"path"
	"strings"
	"testing"

	"github.com/bastionzero/opk-ssh/policy"
	"github.com/bastionzero/opk-ssh/test/integration/ssh_server"
	"github.com/testcontainers/testcontainers-go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

const SudoerUser string = "test"
const UnprivUser string = "test2"
const RootUser string = "root"

func executeCommandAsUser(t *testing.T, container testcontainers.Container, cmd []string, user string) (int, string) {
	// Execute command
	execOpts := []tcexec.ProcessOption{tcexec.Multiplexed(), tcexec.WithUser(user)}
	code, reader, err := container.Exec(TestCtx, cmd, execOpts...)
	require.NoError(t, err)

	// Read stdout/stderr from command execution
	b, err := io.ReadAll(reader)
	require.NoError(t, err)
	t.Logf("Command `%s` returned exit code %d and the following stdout/stderr:\n%s", strings.Join(cmd, " "), code, string(b))

	return code, string(b)
}

func TestAdd(t *testing.T) {
	// Test adding an allowed principal to an opk-ssh policy

	tests := []struct {
		name             string
		binaryPath       string
		useSudo          bool
		cmdUser          string
		desiredPrincipal string
		shouldCmdFail    bool
	}{
		{
			name:             "sudoer user can update root policy",
			binaryPath:       "/etc/opk/opk-ssh",
			useSudo:          true,
			cmdUser:          SudoerUser,
			desiredPrincipal: SudoerUser,
			shouldCmdFail:    false,
		},
		{
			name:             "sudoer user can update root policy with principal != self",
			binaryPath:       "/etc/opk/opk-ssh",
			useSudo:          true,
			cmdUser:          SudoerUser,
			desiredPrincipal: UnprivUser,
			shouldCmdFail:    false,
		},
		{
			name:             "unprivileged user can update their user policy",
			binaryPath:       "/home/test2/.opk/opk-ssh",
			useSudo:          false,
			cmdUser:          UnprivUser,
			desiredPrincipal: UnprivUser,
			shouldCmdFail:    false,
		},
		{
			name:             "unprivileged user cannot add principal != self",
			binaryPath:       "/home/test2/.opk/opk-ssh",
			useSudo:          false,
			cmdUser:          UnprivUser,
			desiredPrincipal: SudoerUser,
			shouldCmdFail:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test container (fresh container for each sub-test)
			container, err := ssh_server.RunOpkSshContainer(
				TestCtx,
				// This test is only using add, so we don't need to set these
				// arguments
				"",
				"",
				"",
				false, // Skip init policy as this test is testing "add" directly
			)
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, container.Terminate(TestCtx), "failed to terminate add_test container")
			})

			// Build add command based on sub-test options
			addCmd := fmt.Sprintf("add foo@example.com %s", tt.desiredPrincipal)
			cmd := []string{tt.binaryPath, addCmd}
			if tt.useSudo {
				cmd = append([]string{"sudo"}, cmd...)
			}

			// Execute add command
			code, _ := executeCommandAsUser(t, container.Container, []string{"/bin/bash", "-c", strings.Join(cmd, " ")}, tt.cmdUser)

			// Determine expected values based on sub-test options
			var expectedPolicyFilepath, expectedUser, expectedGroup string
			if tt.useSudo {
				expectedPolicyFilepath = policy.SystemDefaultPolicyPath
				expectedUser = "root"
				expectedGroup = "root"
			} else {
				expectedPolicyFilepath = path.Join("/home/", tt.cmdUser, ".opk", "policy.yml")
				expectedUser = tt.cmdUser
				expectedGroup = tt.cmdUser
			}

			if tt.shouldCmdFail {
				assert.Equal(t, 1, code, "add command should fail")
				code, policyContents := executeCommandAsUser(t, container.Container, []string{"cat", expectedPolicyFilepath}, RootUser)
				require.Equal(t, 0, code, "failed to read policy file")
				assert.Empty(t, policyContents, "policy file should not be updated")
			} else {
				require.Equal(t, 0, code, "failed to run add command")

				// Assert that the correct policy file is updated
				code, policyContents := executeCommandAsUser(t, container.Container, []string{"cat", expectedPolicyFilepath}, RootUser)
				require.Equal(t, 0, code, "failed to read policy file")
				gotPolicy, err := policy.FromYAML([]byte(policyContents))
				require.NoError(t, err)
				expectedPolicy := &policy.Policy{
					Users: []policy.User{
						{
							Email:      "foo@example.com",
							Principals: []string{tt.desiredPrincipal},
						},
					},
				}
				require.Equal(t, expectedPolicy, gotPolicy)
				// Assert that owner and permissions are still correct
				code, statOutput := executeCommandAsUser(t, container.Container, []string{"stat", "-c", "%U %G %a", expectedPolicyFilepath}, RootUser)
				require.Equal(t, 0, code, "failed to run stat command")
				statOutputSplit := strings.Split(strings.TrimSpace(statOutput), " ")
				require.Len(t, statOutputSplit, 3, "expected stat command to return 3 values")
				require.Equal(t, expectedUser, statOutputSplit[0])  // Assert user
				require.Equal(t, expectedGroup, statOutputSplit[1]) // Assert group
				require.Equal(t, "600", statOutputSplit[2])         // Assert permissions
			}

			// No matter what, if command fails or succeeds, the root policy
			// file should *never* be updated if the command was run without
			// sudo/as unprivileged user
			if !tt.useSudo {
				code, policyContents := executeCommandAsUser(t, container.Container, []string{"cat", policy.SystemDefaultPolicyPath}, RootUser)
				require.Equal(t, 0, code, "failed to read policy file")
				require.Empty(t, policyContents, "system policy file should not be updated if command was run without sudo")
			}
		})
	}
}
