//go:build integration

package integration

import (
	"context"
	"os"
	"os/signal"
	"testing"
)

// TestCtx is marked done when the `go test` binary receives an interrupt signal
// or after all tests in the integration package have finished running
var TestCtx context.Context

func TestMain(m *testing.M) {
	os.Exit(func() int {
		// Do init stuff before all integration tests. defers in this func are
		// called after all the integration tests are complete.

		// Setup global integration CTX that accepts signal interrupt
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		TestCtx = ctx

		return m.Run()
	}())
}
