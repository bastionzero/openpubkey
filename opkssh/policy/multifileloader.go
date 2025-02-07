package policy

import (
	"errors"
	"log"
	"strings"
)

var _ Loader = &MultiFileLoader{}

// FileSource implements policy.Source by returning a string that is expected to
// be a filepath
type FileSource string

func (s FileSource) Source() string {
	return string(s)
}

// MultiFileLoader implements policy.Loader by reading both the system default
// policy (root policy) and user policy (~/.opk/policy.yml where ~ maps to
// Username's home directory)
type MultiFileLoader struct {
	*FileLoader

	Username string
}

func (l *MultiFileLoader) Load() (*Policy, Source, error) {
	policy := new(Policy)

	// Try to load the root policy
	rootPolicy, rootPolicyErr := l.LoadSystemDefaultPolicy()
	if rootPolicyErr != nil {
		log.Println("warning: failed to load system default policy:", rootPolicyErr)
	}

	// Try to load the user policy
	userPolicy, userPolicyFilePath, userPolicyErr := l.LoadUserPolicy(l.Username, true)
	if userPolicyErr != nil {
		log.Println("warning: failed to load user policy:", userPolicyErr)
	}
	// Log warning if no error loading, but userPolicy is empty meaning that
	// there are no valid entries
	if userPolicyErr == nil && len(userPolicy.Users) == 0 {
		log.Printf("warning: user policy %s has no valid user entries; an entry is considered valid if it gives %s access.", userPolicyFilePath, l.Username)
	}

	// Failed to read both policies. Return multi-error
	if rootPolicy == nil && userPolicy == nil {
		return nil, EmptySource{}, errors.Join(rootPolicyErr, userPolicyErr)
	}

	// TODO-Yuval: Optimize by merging duplicate entries instead of blindly
	// appending
	readPaths := []string{}
	if rootPolicy != nil {
		policy.Users = append(policy.Users, rootPolicy.Users...)
		readPaths = append(readPaths, SystemDefaultPolicyPath)
	}
	if userPolicy != nil {
		policy.Users = append(policy.Users, userPolicy.Users...)
		readPaths = append(readPaths, userPolicyFilePath)
	}

	return policy, FileSource(strings.Join(readPaths, ", ")), nil
}
