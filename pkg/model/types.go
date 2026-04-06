package model

type OSInfo struct {
	ID         string // debian, ubuntu, rhel, centos, rocky, alma, etc.
	VersionID  string // 22.04, 12, 9, etc.
	PrettyName string
}

type Package struct {
	Name      string
	Version   string
	Ecosystem string // deb, rpm
	Source    string // dpkg-query, rpm
}

type Severity string

const (
	SeverityUnknown  Severity = "UNKNOWN"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Advisory holds metadata for a security advisory.
type Advisory struct {
	ID          string // CVE-2023-1234 or GHSA-xxx
	Title       string
	Description string
	Severity    Severity
	CVSS        *CVSS
	References  []string
	Published   string
	Modified    string
	Source      string // "osv", "ubuntu-usn", "rhel", etc.
	FixedBy     string // Fixed version
	URL         string // Advisory URL
}

type CVSS struct {
	Score    float64
	Vector   string
	Severity Severity
}

type Finding struct {
	Package  Package
	VulnID   string
	Title    string
	Severity Severity
	FixedBy  string
	URL      string
	Advisory *Advisory // Populated when matched from a live source
	IsStub   bool      // True if from stub rules rather than live CVE data
}

type ScanResult struct {
	OS       OSInfo
	Packages []Package
	Findings []Finding
}
