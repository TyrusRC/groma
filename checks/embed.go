// Package checks embeds groma's bundled CVE check library into the binary
// so that `groma scan` runs the full check set with no --checks flag and
// no files on disk — including for users who installed with `go install`
// and never cloned the repo.
package checks

import "embed"

// Examples holds the bundled YAML CVE checks. Load them with
// internal/checks.LoadChecksFS(checks.Examples, "examples").
//
//go:embed examples/*.yaml
var Examples embed.FS
