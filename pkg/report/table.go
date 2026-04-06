package report

import (
	"fmt"
	"os"
	"strings"

	"boxguard/pkg/model"

	"github.com/jedib0t/go-pretty/v6/table"
)

type tableReporter struct{}

func (t *tableReporter) Emit(res model.ScanResult) error {
	fmt.Printf("OS: %s (ID=%s, VERSION_ID=%s)\n\n", res.OS.PrettyName, res.OS.ID, res.OS.VersionID)

	w := table.NewWriter()
	w.SetOutputMirror(os.Stdout)
	w.AppendHeader(table.Row{"SEV", "PKG", "VERSION", "VULN", "TITLE", "FIX", "SOURCE", "CVSS"})

	for _, f := range res.Findings {
		// Resolve display source
		source := "STUB"
		if !f.IsStub && f.Advisory != nil {
			source = f.Advisory.Source
		}

		// CVSS score column
		cvss := "-"
		if f.Advisory != nil && f.Advisory.CVSS != nil {
			cvss = fmt.Sprintf("%.1f", f.Advisory.CVSS.Score)
		}

		// Truncate long titles
		title := f.Title
		if len(title) > 50 {
			title = title[:47] + "..."
		}

		w.AppendRow(table.Row{
			f.Severity,
			f.Package.Name,
			f.Package.Version,
			f.VulnID,
			title,
			f.FixedBy,
			source,
			cvss,
		})
	}

	w.Render()

	// Summary line
	fmt.Printf("\nPackages: %d, Findings: %d\n", len(res.Packages), len(res.Findings))

	// Source breakdown
	sourceCount := make(map[string]int)
	stubCount := 0
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, f := range res.Findings {
		if f.IsStub {
			stubCount++
		} else if f.Advisory != nil {
			sourceCount[f.Advisory.Source]++
		}

		// Severity counts
		switch f.Severity {
		case model.SeverityCritical:
			criticalCount++
		case model.SeverityHigh:
			highCount++
		case model.SeverityMedium:
			mediumCount++
		case model.SeverityLow:
			lowCount++
		}
	}

	// Severity summary lines
	if criticalCount > 0 {
		fmt.Printf("🔴 Critical: %d\n", criticalCount)
	}
	if highCount > 0 {
		fmt.Printf("🟠 High: %d\n", highCount)
	}
	if mediumCount > 0 {
		fmt.Printf("🟡 Medium: %d\n", mediumCount)
	}
	if lowCount > 0 {
		fmt.Printf("🟢 Low: %d\n", lowCount)
	}

	if stubCount > 0 {
		fmt.Printf("📋 Stub findings: %d\n", stubCount)
	}
	for source, count := range sourceCount {
		fmt.Printf("📡 %s findings: %d\n", strings.ToUpper(source), count)
	}

	return nil
}
