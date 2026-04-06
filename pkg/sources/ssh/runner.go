package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

type Config struct {
	Host    string
	User    string
	KeyPath string
	Port    int
}

type Runner struct {
	client *ssh.Client
}

func NewRunner(ctx context.Context, cfg Config) (*Runner, error) {
	key, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("key parse: %w", err)
	}

	c := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: optional known_hosts verification
		Timeout:         15 * time.Second,
	}

	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	client, err := ssh.Dial("tcp", addr, c)
	if err != nil {
		return nil, err
	}
	return &Runner{client: client}, nil
}

func (r *Runner) Run(ctx context.Context, command string) (string, error) {
	sess, err := r.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	stdout, err := sess.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := sess.Start(command); err != nil {
		return "", err
	}

	out, _ := io.ReadAll(stdout)
	errOut, _ := io.ReadAll(stderr)
	waitCh := make(chan error, 1)
	go func() { waitCh <- sess.Wait() }()

	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		return "", ctx.Err()
	case err := <-waitCh:
		if err != nil {
			return "", fmt.Errorf("cmd err: %s", string(errOut))
		}
		return string(out), nil
	}
}

func (r *Runner) Close() { _ = r.client.Close() }
