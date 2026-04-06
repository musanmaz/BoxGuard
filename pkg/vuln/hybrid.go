package vuln

import (
	"boxguard/pkg/model"
	"fmt"
	"log"
	"strings"
	"sync"
)

const maxConcurrentOSVQueries = 5

type HybridMatcher struct {
	stubDB *stubDB
	osvDB  *OSVDB
	usnDB  *USNDB
}

func NewHybridMatcher() *HybridMatcher {
	return &HybridMatcher{
		stubDB: &stubDB{},
		osvDB:  NewOSVDB(),
		usnDB:  NewUSNDB(),
	}
}

func (h *HybridMatcher) MatchPackages(os model.OSInfo, pkgs []model.Package) []model.Finding {
	var findings []model.Finding

	log.Printf("🔍 Vulnerability scan started — %d packages, OS: %s %s", len(pkgs), os.ID, os.VersionID)

	// Stub rules (fallback)
	stubFindings := h.stubDB.MatchPackages(os, pkgs)
	log.Printf("📋 Stub findings: %d", len(stubFindings))
	for _, f := range stubFindings {
		f.IsStub = true
		findings = append(findings, f)
	}

	// OSV.dev CVE lookup
	log.Printf("🌐 OSV.dev scan started...")
	osvFindings := h.matchOSV(os, pkgs)
	log.Printf("🌐 OSV findings: %d", len(osvFindings))
	findings = append(findings, osvFindings...)

	// Ubuntu USN RSS for Ubuntu targets
	if os.ID == "ubuntu" {
		log.Printf("📡 Ubuntu USN feed scan started...")
		usnFindings := h.matchUSN(os, pkgs)
		log.Printf("📡 USN findings: %d", len(usnFindings))
		findings = append(findings, usnFindings...)
	}

	// Deduplicate (same package may appear with multiple CVEs)
	originalCount := len(findings)
	findings = h.deduplicateFindings(findings)
	log.Printf("🔄 Deduplication: %d -> %d findings", originalCount, len(findings))

	log.Printf("✅ Scan finished — total findings: %d", len(findings))
	return findings
}

func (h *HybridMatcher) matchOSV(os model.OSInfo, pkgs []model.Package) []model.Finding {
	var findings []model.Finding

	var importantPkgs []model.Package
	for _, pkg := range pkgs {
		if h.isImportantPackage(pkg.Name) {
			importantPkgs = append(importantPkgs, pkg)
		}
	}

	if len(importantPkgs) == 0 {
		log.Printf("⚠️  No important packages found for OSV")
		return findings
	}

	log.Printf("🎯 OSV: %d important packages: %v", len(importantPkgs),
		func() []string {
			var names []string
			for _, p := range importantPkgs {
				names = append(names, p.Name)
			}
			return names
		}())

	var wg sync.WaitGroup
	findingsChan := make(chan []model.Finding, len(importantPkgs))
	semaphore := make(chan struct{}, maxConcurrentOSVQueries)

	for _, pkg := range importantPkgs {
		wg.Add(1)
		go func(p model.Package) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			advisories, err := h.osvDB.QueryPackage(p)
			if err != nil {
				if !strings.Contains(err.Error(), "400") {
					log.Printf("OSV query error for %s: %v", p.Name, err)
				}
				return
			}

			var pkgFindings []model.Finding
			for _, advisory := range advisories {
				if h.isVulnerable(p, advisory) {
					finding := model.Finding{
						Package:  p,
						VulnID:   advisory.ID,
						Title:    advisory.Title,
						Severity: advisory.Severity,
						FixedBy:  advisory.FixedBy,
						URL:      advisory.URL,
						Advisory: &advisory,
						IsStub:   false,
					}
					pkgFindings = append(pkgFindings, finding)
				}
			}

			if len(pkgFindings) > 0 {
				findingsChan <- pkgFindings
			}
		}(pkg)
	}

	go func() {
		wg.Wait()
		close(findingsChan)
	}()

	for pkgFindings := range findingsChan {
		findings = append(findings, pkgFindings...)
	}

	return findings
}

func (h *HybridMatcher) matchUSN(os model.OSInfo, pkgs []model.Package) []model.Finding {
	var findings []model.Finding

	log.Printf("📡 Fetching advisories from USN feed...")
	advisories, err := h.usnDB.GetAdvisories()
	if err != nil {
		log.Printf("❌ USN feed error: %v", err)
		return findings
	}

	log.Printf("📡 Received %d advisories from USN", len(advisories))

	pkgMap := make(map[string]model.Package)
	for _, pkg := range pkgs {
		normalizedName := strings.ToLower(pkg.Name)
		pkgMap[normalizedName] = pkg
	}

	log.Printf("📦 %d packages prepared for USN matching", len(pkgMap))

	for _, advisory := range advisories {
		for pkgName, pkg := range pkgMap {
			if h.isPackageMatch(pkgName, advisory, pkg) {
				if h.isVulnerable(pkg, advisory) {
					finding := model.Finding{
						Package:  pkg,
						VulnID:   advisory.ID,
						Title:    advisory.Title,
						Severity: advisory.Severity,
						FixedBy:  advisory.FixedBy,
						URL:      advisory.URL,
						Advisory: &advisory,
						IsStub:   false,
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

func (h *HybridMatcher) isVulnerable(pkg model.Package, advisory model.Advisory) bool {
	// Simple version comparison; production code would use proper version parsing.
	if advisory.FixedBy == "" {
		return true // assume vulnerable if no fixed version
	}

	currentVer := normalizeVersion(pkg.Version)
	fixedVer := normalizeVersion(advisory.FixedBy)

	return compareVersions(currentVer, fixedVer) < 0
}

// isImportantPackage limits matching to a curated set of package names.
func (h *HybridMatcher) isImportantPackage(pkgName string) bool {
	importantPackages := map[string]bool{
		"openssl":    true,
		"sudo":       true,
		"bash":       true,
		"python":     true,
		"python3":    true,
		"curl":       true,
		"wget":       true,
		"git":        true,
		"nginx":      true,
		"apache2":    true,
		"mysql":      true,
		"postgresql": true,
		"docker":     true,
		"kubernetes": true,
		"nodejs":     true,
		"php":        true,
		"ruby":       true,
		"java":       true,
		"golang":     true,
		"rust":       true,
	}

	return importantPackages[strings.ToLower(pkgName)]
}

// isPackageMatch performs heuristic matching between package names and advisory text.
func (h *HybridMatcher) isPackageMatch(pkgName string, advisory model.Advisory, pkg model.Package) bool {
	if strings.Contains(strings.ToLower(advisory.Title), "linux kernel") {
		kernelPackages := map[string]bool{
			"linux-image":      true,
			"linux-headers":    true,
			"linux-generic":    true,
			"linux-lowlatency": true,
		}

		if !kernelPackages[strings.ToLower(pkg.Name)] {
			return false
		}
	}

	desc := strings.ToLower(advisory.Description)
	pkgNameLower := strings.ToLower(pkgName)

	words := strings.Fields(desc)
	for _, word := range words {
		if word == pkgNameLower {
			return true
		}

		// e.g. python3 vs python
		if strings.HasPrefix(word, pkgNameLower) || strings.HasSuffix(word, pkgNameLower) {
			return true
		}
	}

	return false
}

func (h *HybridMatcher) deduplicateFindings(findings []model.Finding) []model.Finding {
	seen := make(map[string]bool)
	var unique []model.Finding

	for _, f := range findings {
		key := fmt.Sprintf("%s-%s-%s", f.Package.Name, f.VulnID, f.Package.Version)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}

	return unique
}

func normalizeVersion(version string) string {
	return strings.TrimSpace(version)
}

func compareVersions(v1, v2 string) int {
	if v1 < v2 {
		return -1
	} else if v1 > v2 {
		return 1
	}
	return 0
}
