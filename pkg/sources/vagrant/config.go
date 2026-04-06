package vagrant

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"boxguard/pkg/sources/ssh"
)

// SSHConfig parses output from `vagrant ssh-config`.
func SSHConfig(ctx context.Context, vagrantDir, machine string) (ssh.Config, error) {
	args := []string{"ssh-config"}
	if machine != "" {
		args = append(args, machine)
	}
	cmd := exec.CommandContext(ctx, "vagrant", args...)
	if vagrantDir != "" {
		cmd.Dir = vagrantDir
	}

	out, err := cmd.Output()
	if err != nil {
		return ssh.Config{}, fmt.Errorf("vagrant ssh-config: %w", err)
	}

	cfg := ssh.Config{Port: 22}
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "HostName":
			cfg.Host = fields[1]
		case "User":
			cfg.User = fields[1]
		case "Port":
			p, _ := strconv.Atoi(fields[1])
			cfg.Port = p
		case "IdentityFile":
			cfg.KeyPath = strings.Trim(fields[1], "\"")
		}
	}
	if err := s.Err(); err != nil {
		return ssh.Config{}, err
	}
	if cfg.Host == "" || cfg.User == "" || cfg.KeyPath == "" {
		return ssh.Config{}, fmt.Errorf("missing required ssh-config fields")
	}
	return cfg, nil
}
