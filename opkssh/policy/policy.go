package policy

import (
	"fmt"
	"log"

	"gopkg.in/yaml.v3"
)

// User is an opk-ssh policy user entry
type User struct {
	// Email is the user's email. It is the expected value used when comparing
	// against an id_token's email claim
	Email string `yaml:"email"`
	// Principals is a list of allowed principals
	Principals []string `yaml:"principals"`
	// Sub        string   `yaml:"sub,omitempty"`
}

// Policy represents an opk-ssh policy
type Policy struct {
	// Users is a list of all user entries in the policy
	Users []User `yaml:"users"`
}

// FromYAML decodes YAML encoded input into policy.Policy
func FromYAML(input []byte) (*Policy, error) {
	policy := &Policy{}
	if err := yaml.Unmarshal(input, policy); err != nil {
		return nil, fmt.Errorf("error unmarshalling input to policy.Policy: %w", err)
	}
	return policy, nil
}

// AddAllowedPrincipal adds a new allowed principal to the user whose email is
// equal to userEmail. If no user can be found with the email userEmail, then a
// new user entry is added with an initial allowed principals list containing
// principal. No changes are made if the principal is already allowed for this
// user.
func (p *Policy) AddAllowedPrincipal(principal string, userEmail string) {
	userExists := false
	if len(p.Users) != 0 {
		// search to see if the current user already has an entry in the policy
		// file
		for i := range p.Users {
			user := &p.Users[i]
			if user.Email == userEmail {
				principalExists := false
				for _, p := range user.Principals {
					// if the principal already exists for this user, then skip
					if p == principal {
						log.Printf("User with email %s already has access under the principal %s, skipping...\n", userEmail, principal)
						principalExists = true
					}
				}

				if !principalExists {
					user.Principals = append(user.Principals, principal)
					log.Printf("Successfully added user with email %s with principal %s to the policy file\n", userEmail, principal)
				}
				userExists = true
			}
		}
	}

	// if the policy is empty or if no user found with userEmail, then create a
	// new entry
	if len(p.Users) == 0 || !userExists {
		newUser := User{
			Email:      userEmail,
			Principals: []string{principal},
		}
		// add the new user to the list of users in the policy
		p.Users = append(p.Users, newUser)
	}
}

// ToYAML encodes the policy into YAML
func (p *Policy) ToYAML() ([]byte, error) {
	marshaledData, err := yaml.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}

	return marshaledData, nil
}

// Source declares the minimal interface to describe the source of a fetched
// opk-ssh policy (i.e. where the policy is retrieved from)
type Source interface {
	// Source returns a string describing the source of an opk-ssh policy. The
	// returned value is empty if there is no information about its source
	Source() string
}

var _ Source = &EmptySource{}

// EmptySource implements policy.Source and returns an empty string as the
// source
type EmptySource struct{}

func (EmptySource) Source() string { return "" }

// Loader declares the minimal interface to retrieve an opk-ssh policy from an
// arbitrary source
type Loader interface {
	// Load fetches an opk-ssh policy and returns information describing its
	// source. If an error occurs, all return values are nil except the error
	// value
	Load() (*Policy, Source, error)
}
