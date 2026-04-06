package vuln

import (
	"boxguard/pkg/model"
	"strconv"
	"strings"
)

type stubDB struct{}

func NewStubDB() Matcher { return &stubDB{} }

// Minimal example rules for demonstration only:
// - openssl major < 3 => HIGH
// - sudo major < 2 => MEDIUM (rough)
func (s *stubDB) MatchPackages(os model.OSInfo, pkgs []model.Package) []model.Finding {
	var out []model.Finding
	for _, p := range pkgs {
		name := strings.ToLower(p.Name)
		maj := parseMajor(p.Version)
		switch name {
		case "openssl":
			if maj > 0 && maj < 3 {
				out = append(out, model.Finding{Package: p, VulnID: "STUB-OPENSSL-MAJOR<3",
					Title: "OpenSSL major < 3", Severity: model.SeverityHigh, FixedBy: "3.x", URL: "https://openssl.org"})
			}
		case "sudo":
			if maj > 0 && maj < 2 { // rough 1.x line
				out = append(out, model.Finding{Package: p, VulnID: "STUB-SUDO-MAJOR<2",
					Title: "sudo major < 2 (example)", Severity: model.SeverityMedium, FixedBy: "1.9+", URL: "https://www.sudo.ws/"})
			}
		}
	}
	return out
}

func parseMajor(v string) int {
	// Debian/RPM versions are complex; this only reads the first integer as a rough heuristic
	for i := 0; i < len(v); i++ {
		if v[i] >= '0' && v[i] <= '9' {
			j := i
			for j < len(v) && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			n, _ := strconv.Atoi(v[i:j])
			return n
		}
	}
	return 0
}
