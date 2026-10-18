package compliance

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// SSHExecutor runs every compliance command over one shared, already-
// authenticated SSH connection (internal/audit.Dial) — a real audit can
// have dozens of <custom_item> checks, and reconnecting per command would
// be both slow and noisy on the target.
type SSHExecutor struct {
	Client *ssh.Client
}

func (e *SSHExecutor) RunCommand(_ context.Context, cmd string) (string, error) {
	session, err := e.Client.NewSession()
	if err != nil {
		return "", fmt.Errorf("opening SSH session: %w", err)
	}
	defer session.Close()
	out, err := session.CombinedOutput(cmd)
	return string(out), err
}
