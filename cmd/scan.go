package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"boxguard/pkg/inventory"
	"boxguard/pkg/model"
	"boxguard/pkg/report"
	sshsrc "boxguard/pkg/sources/ssh"
	vag "boxguard/pkg/sources/vagrant"
	"boxguard/pkg/vuln"

	"github.com/spf13/cobra"
)

var (
	vagrantPath    string
	vagrantMachine string
	sshHost        string
	sshUser        string
	sshKey         string
	sshPort        int
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan the target machine",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		var cfg sshsrc.Config
		var err error

		if vagrantPath != "" || vagrantMachine != "" {
			cfg, err = vag.SSHConfig(ctx, vagrantPath, vagrantMachine)
			if err != nil {
				return err
			}
		} else if sshHost != "" {
			if sshUser == "" || sshKey == "" {
				return errors.New("--ssh-user and --ssh-key are required with --ssh-host")
			}
			cfg = sshsrc.Config{Host: sshHost, User: sshUser, KeyPath: sshKey, Port: sshPort}
		} else {
			return errors.New("no target specified: use --vagrant-path / --vagrant-machine or --ssh-host")
		}

		runner, err := sshsrc.NewRunner(ctx, cfg)
		if err != nil {
			return err
		}
		defer runner.Close()

		osInfo, err := inventory.DetectOS(ctx, runner)
		if err != nil {
			return fmt.Errorf("OS detection failed: %w", err)
		}

		pkgs, err := inventory.ListPackages(ctx, runner, osInfo)
		if err != nil {
			return fmt.Errorf("package inventory failed: %w", err)
		}

		matcher := vuln.NewHybridMatcher()
		findings := matcher.MatchPackages(osInfo, pkgs)

		reporter, err := report.New(outputFormat)
		if err != nil {
			return err
		}
		return reporter.Emit(model.ScanResult{OS: osInfo, Packages: pkgs, Findings: findings})
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVar(&vagrantPath, "vagrant-path", "", "directory containing Vagrantfile (optional)")
	scanCmd.Flags().StringVar(&vagrantMachine, "vagrant-machine", "", "Vagrant machine name (optional)")
	scanCmd.Flags().StringVar(&sshHost, "ssh-host", "", "SSH host (e.g. 127.0.0.1)")
	scanCmd.Flags().StringVar(&sshUser, "ssh-user", "", "SSH username")
	scanCmd.Flags().StringVar(&sshKey, "ssh-key", "", "SSH private key path")
	scanCmd.Flags().IntVar(&sshPort, "ssh-port", 22, "SSH port")
}
