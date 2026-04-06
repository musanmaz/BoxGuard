package vuln

import (
	"boxguard/pkg/model"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type USNFeed struct {
	XMLName xml.Name   `xml:"rss"`
	Channel USNChannel `xml:"channel"`
}

type USNChannel struct {
	Items []USNItem `xml:"item"`
}

type USNItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	GUID        string `xml:"guid"`
}

type USNDB struct {
	client  *http.Client
	feedURL string
}

func NewUSNDB() *USNDB {
	return &USNDB{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		feedURL: "https://ubuntu.com/security/notices/rss.xml",
	}
}

func (u *USNDB) GetAdvisories() ([]model.Advisory, error) {
	req, err := http.NewRequest("GET", u.feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build USN feed request: %w", err)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("USN feed request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("USN feed HTTP error: %d", resp.StatusCode)
	}

	var feed USNFeed
	if err := xml.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, fmt.Errorf("decode USN feed: %w", err)
	}

	var advisories []model.Advisory
	for _, item := range feed.Channel.Items {
		// Extract USN ID (e.g. USN-1234-1)
		usnID := extractUSNID(item.Title)
		if usnID == "" {
			continue
		}

		// CVE IDs from description text
		cves := extractCVEs(item.Description)
		if len(cves) == 0 {
			continue
		}

		// One advisory per CVE
		for _, cve := range cves {
			advisory := model.Advisory{
				ID:          cve,
				Title:       item.Title,
				Description: item.Description,
				Source:      "ubuntu-usn",
				URL:         item.Link,
				Published:   parsePubDate(item.PubDate),
			}

			// Severity from description keywords
			advisory.Severity = extractSeverity(item.Description)

			advisories = append(advisories, advisory)
		}
	}

	return advisories, nil
}

func extractUSNID(title string) string {
	// Parse USN-1234-1 style ID from title
	if strings.HasPrefix(title, "USN-") {
		parts := strings.Split(title, " ")
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return ""
}

func extractCVEs(description string) []string {
	var cves []string
	// Find CVE-YYYY-NNNN tokens
	words := strings.Fields(description)
	for _, word := range words {
		if strings.HasPrefix(word, "CVE-") {
			cves = append(cves, word)
		}
	}
	return cves
}

func extractSeverity(description string) model.Severity {
	desc := strings.ToLower(description)

	if strings.Contains(desc, "critical") {
		return model.SeverityCritical
	}
	if strings.Contains(desc, "high") {
		return model.SeverityHigh
	}
	if strings.Contains(desc, "medium") {
		return model.SeverityMedium
	}
	if strings.Contains(desc, "low") {
		return model.SeverityLow
	}

	return model.SeverityUnknown
}

func parsePubDate(pubDate string) string {
	// Parse RFC822 pubDate
	t, err := time.Parse(time.RFC822, pubDate)
	if err != nil {
		return pubDate
	}
	return t.Format("2006-01-02")
}
