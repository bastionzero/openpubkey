package idp

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestClientFakeOp(t *testing.T) {
	redirectUri := "http://localhost:3001/login-callback"

	idp, err := New(redirectUri)
	require.NoError(t, err)

	signerAlg := jwa.ES256
	op := &providers.StandardOp{
		ClientID:       "client_id",
		ClientSecret:   "secret secret",
		Scopes:         []string{"openid", "email", "profile"},
		RedirectURIs:   []string{redirectUri},
		GQSign:         false,
		OpenBrowser:    false,
		HttpClient:     nil,
		IssuedAtOffset: 1 * time.Minute,
	}
	op.SetIssuer("http://localhost:17171")
	idp.SetHook(op)

	err = idp.Start()
	require.NoError(t, err)

	// Wait until the server is listening
	require.Eventually(t, func() bool {
		return idp.server != nil
	}, 30*time.Second, 100*time.Millisecond)

	signer, err := util.GenKeyPair(signerAlg)
	require.NoError(t, err)
	c, err := client.New(op, client.WithSigner(signer, jwa.ES256))
	require.NoError(t, err)

	pkt, err := c.Auth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, pkt)
}
