package vuln

import "boxguard/pkg/model"

type Matcher interface {
	MatchPackages(os model.OSInfo, pkgs []model.Package) []model.Finding
}
