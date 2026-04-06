package vuln

import (
	"boxguard/pkg/model"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type OSVQuery struct {
	Commit  string `json:"commit,omitempty"`
	Version string `json:"version,omitempty"`
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}

type OSVResponse struct {
	Vulns []OSVVuln `json:"vulns"`
}

type OSVVuln struct {
	ID               string        `json:"id"`
	Summary          string        `json:"summary"`
	Details          string        `json:"details"`
	Modified         time.Time     `json:"modified"`
	Published        time.Time     `json:"published"`
	References       []OSVRef      `json:"references"`
	Affected         []OSVAffected `json:"affected"`
	DatabaseSpecific struct {
		CVSS *OSVCVSS `json:"cvss,omitempty"`
	} `json:"database_specific"`
}

type OSVRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type OSVAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []OSVRange `json:"ranges"`
	Fixed  string     `json:"fixed,omitempty"`
}

type OSVRange struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced string `json:"introduced,omitempty"`
		Fixed      string `json:"fixed,omitempty"`
	} `json:"events"`
}

type OSVCVSS struct {
	Score  float64 `json:"score"`
	Vector string  `json:"vector"`
}

type OSVDB struct {
	client *http.Client
}

func NewOSVDB() *OSVDB {
	return &OSVDB{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (o *OSVDB) QueryPackage(pkg model.Package) ([]model.Advisory, error) {
	// OSV.dev API endpoint
	apiURL := "https://api.osv.dev/v1/query"

	// Map Debian packages to OSV ecosystem
	ecosystem := "DEB"
	if pkg.Ecosystem == "rpm" {
		ecosystem = "GIT"
	}

	// Limit to important packages for performance
	if !o.isImportantPackage(pkg.Name) {
		return nil, nil
	}

	query := OSVQuery{
		Package: struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		}{
			Name:      pkg.Name,
			Ecosystem: ecosystem,
		},
		Version: pkg.Version,
	}

	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("marshal query: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(string(queryJSON)))
	if err != nil {
		return nil, fmt.Errorf("build HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSV API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API error: %d", resp.StatusCode)
	}

	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("decode OSV response: %w", err)
	}

	var advisories []model.Advisory
	for _, vuln := range osvResp.Vulns {
		// Only CVE IDs
		if !strings.HasPrefix(vuln.ID, "CVE-") {
			continue
		}

		// Map CVSS score to severity
		severity := model.SeverityUnknown
		if vuln.DatabaseSpecific.CVSS != nil {
			score := vuln.DatabaseSpecific.CVSS.Score
			switch {
			case score >= 9.0:
				severity = model.SeverityCritical
			case score >= 7.0:
				severity = model.SeverityHigh
			case score >= 4.0:
				severity = model.SeverityMedium
			case score >= 0.1:
				severity = model.SeverityLow
			}
		}

		// Find fixed version if present
		fixedBy := ""
		for _, affected := range vuln.Affected {
			if affected.Fixed != "" {
				fixedBy = affected.Fixed
				break
			}
		}

		// Collect reference URLs
		var references []string
		for _, ref := range vuln.References {
			if ref.Type == "WEB" || ref.Type == "ADVISORY" {
				references = append(references, ref.URL)
			}
		}

		advisory := model.Advisory{
			ID:          vuln.ID,
			Title:       vuln.Summary,
			Description: vuln.Details,
			Severity:    severity,
			Source:      "osv",
			Published:   vuln.Published.Format("2006-01-02"),
			Modified:    vuln.Modified.Format("2006-01-02"),
			References:  references,
			FixedBy:     fixedBy,
		}

		if vuln.DatabaseSpecific.CVSS != nil {
			advisory.CVSS = &model.CVSS{
				Score:    vuln.DatabaseSpecific.CVSS.Score,
				Vector:   vuln.DatabaseSpecific.CVSS.Vector,
				Severity: severity,
			}
		}

		advisories = append(advisories, advisory)
	}

	return advisories, nil
}

// isImportantPackage limits OSV queries to a curated package set.
func (o *OSVDB) isImportantPackage(pkgName string) bool {
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
