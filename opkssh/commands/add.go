package commands

import (
	"errors"
	"fmt"
	"os"

	"github.com/bastionzero/opk-ssh/policy"
)

// AddCmd provides functionality to read and update the opk-ssh policy file
type AddCmd struct {
	PolicyFileLoader *policy.FileLoader

	// Username is the username to lookup when the system policy file cannot be
	// read and we fallback to the user's policy file.
	//
	// See AddCmd.LoadPolicy for more details.
	Username string
}

// LoadPolicy reads the opk-ssh policy at the policy.SystemDefaultPolicyPath. If
// there is a permission error when reading this file, then the user's local
// policy file (defined as ~/.opk/policy.yml where ~ maps to AddCmd.Username's
// home directory) is read instead.
//
// If successful, returns the parsed policy and filepath used to read the
// policy. Otherwise, a non-nil error is returned.
func (a *AddCmd) LoadPolicy() (*policy.Policy, string, error) {
	// Try to read system policy first
	systemPolicy, err := a.PolicyFileLoader.LoadSystemDefaultPolicy()
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			// If current process doesn't have permission, try reading the user
			// policy file.
			userPolicy, policyFilePath, err := a.PolicyFileLoader.LoadUserPolicy(a.Username, false)
			if err != nil {
				return nil, "", err
			}
			return userPolicy, policyFilePath, nil
		} else {
			// Non-permission error (e.g. system policy file missing or invalid
			// permission bits set). Return error
			return nil, "", err
		}
	}

	return systemPolicy, policy.SystemDefaultPolicyPath, nil
}

// Add adds a new allowed principal to the user whose email is equal to
// userEmail. The current policy file is read and modified.
//
// If successful, returns the policy filepath updated. Otherwise, returns a
// non-nil error
func (a *AddCmd) Add(userEmail string, principal string) (string, error) {
	// Read current policy
	currentPolicy, policyFilePath, err := a.LoadPolicy()
	if err != nil {
		return "", fmt.Errorf("failed to load current policy: %w", err)
	}

	// Update policy
	currentPolicy.AddAllowedPrincipal(principal, userEmail)

	// Dump contents back to disk
	err = a.PolicyFileLoader.Dump(currentPolicy, policyFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to write updated policy: %w", err)
	}

	return policyFilePath, nil
}
