package inventory

import (
	"context"
	"strings"

	"boxguard/pkg/model"
	"boxguard/pkg/sources/ssh"
)

// listRPM returns the RPM package list.
func listRPM(ctx context.Context, r *ssh.Runner) ([]model.Package, error) {
	cmd := `rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null || true`
	out, err := r.Run(ctx, cmd)
	if err != nil {
		return nil, err
	}
	var pkgs []model.Package
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		pkgs = append(pkgs, model.Package{
			Name:      f[0],
			Version:   f[1],
			Ecosystem: "rpm",
			Source:    "rpm",
		})
	}
	return pkgs, nil
}
