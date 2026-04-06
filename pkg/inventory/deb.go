package inventory

import (
	"context"
	"regexp"
	"strings"

	"boxguard/pkg/model"
	"boxguard/pkg/sources/ssh"
)

var kvRe = regexp.MustCompile(`^([A-Z_]+)=(.*)$`)

func DetectOS(ctx context.Context, r *ssh.Runner) (model.OSInfo, error) {
	// /etc/os-release parse (ID, VERSION_ID, PRETTY_NAME)
	out, err := r.Run(ctx, "cat /etc/os-release")
	if err != nil {
		return model.OSInfo{}, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if sub := kvRe.FindStringSubmatch(line); len(sub) == 3 {
			key := sub[1]
			val := strings.Trim(sub[2], "\"")
			m[key] = val
		}
	}
	return model.OSInfo{ID: m["ID"], VersionID: m["VERSION_ID"], PrettyName: m["PRETTY_NAME"]}, nil
}

func ListPackages(ctx context.Context, r *ssh.Runner, os model.OSInfo) ([]model.Package, error) {
	switch os.ID {
	case "debian", "ubuntu":
		return listDPKG(ctx, r)
	case "rhel", "centos", "rocky", "alma":
		return listRPM(ctx, r)
	default:
		// try dpkg first, then rpm
		pkgs, err := listDPKG(ctx, r)
		if err == nil && len(pkgs) > 0 {
			return pkgs, nil
		}
		return listRPM(ctx, r)
	}
}

func listDPKG(ctx context.Context, r *ssh.Runner) ([]model.Package, error) {
	cmd := `dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null || true`
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
			Ecosystem: "deb",
			Source:    "dpkg-query",
		})
	}
	return pkgs, nil
}
