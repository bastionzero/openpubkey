package policy

import (
	"encoding/json"
	"fmt"

	"github.com/openpubkey/openpubkey/pktoken"
	"golang.org/x/exp/slices"
)

// Enforcer evaluates opk-ssh policy to determine if the desired principal is
// permitted
type Enforcer struct {
	PolicyLoader Loader
}

// CheckPolicy loads the opk-ssh policy and checks to see if there is a policy
// permitting access to principalDesired for the user identified by the PKT's
// email claim. Returns nil if access is granted. Otherwise, an error is
// returned.
//
// It is recommended to verify the pkt first before calling this function.
func (p *Enforcer) CheckPolicy(principalDesired string, pkt *pktoken.PKToken) error {
	policy, source, err := p.PolicyLoader.Load()
	if err != nil {
		return fmt.Errorf("error loading policy: %w", err)
	}

	sourceStr := source.Source()
	if sourceStr == "" {
		sourceStr = "<policy source unknown>"
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return fmt.Errorf("error unmarshalling pk token payload: %w", err)
	}

	for _, user := range policy.Users {
		// check each entry to see if the user in the claims is included
		if string(claims.Email) == user.Email {
			// if they are, then check if the desired principal is allowed
			if slices.Contains(user.Principals, principalDesired) {
				// access granted
				return nil
			}
		}
	}

	return fmt.Errorf("no policy to allow %s to assume %s, check policy config at %s", claims.Email, principalDesired, sourceStr)
}
