package provider

import (
	"context"

	"github.com/awnumar/memguard"
	"github.com/openpubkey/openpubkey/client"
)

// RefreshableOP declares the minimal interface for an OPK OIDC client that
// interacts with an OP (OpenID provider) that allows for its token to be
// refreshed.
type RefreshableOP interface {
	client.OpenIdProvider
	// Refresh returns a refreshed ID token
	Refresh(ctx context.Context) (*memguard.LockedBuffer, error)
}

// Config declares the minimal interface for an OP (OpenID provider) config. It
// provides methods to get configuration values for a specific OIDC client
// implementation.
type Config interface {
	// ClientID returns the registered client identifier that is valid at the OP
	// issuer
	ClientID() string
	// IssuerUrl returns the OP's issuer URL identifier
	IssuerUrl() string
}
