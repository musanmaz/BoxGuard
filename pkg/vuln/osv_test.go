package vuln

import (
	"boxguard/pkg/model"
	"testing"
)

func TestOSVDB_QueryPackage(t *testing.T) {
	osv := NewOSVDB()

	// Test package
	pkg := model.Package{
		Name:      "openssl",
		Version:   "1.1.0g-2ubuntu4",
		Ecosystem: "deb",
		Source:    "dpkg-query",
	}

	advisories, err := osv.QueryPackage(pkg)
	if err != nil {
		t.Logf("OSV query error (may be expected): %v", err)
		// Network or API failures are acceptable in this smoke test
		return
	}

	if len(advisories) > 0 {
		t.Logf("Advisory count: %d", len(advisories))
		for _, adv := range advisories {
			t.Logf("Advisory: %s - %s", adv.ID, adv.Title)
		}
	}
}
