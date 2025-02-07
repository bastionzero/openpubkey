// Package projectpath is used internally by the integration tests to get the
// root folder of the opk-ssh project
package projectpath

import (
	"path/filepath"
	"runtime"
)

// Source: https://stackoverflow.com/a/58294680
var (
	_, b, _, _ = runtime.Caller(0)

	// Root is the root folder of the opk-ssh project
	Root = filepath.Join(filepath.Dir(b), "../..")
)
