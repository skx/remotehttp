package remotehttp

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Test fetching remote things we shouldn't is denied.
func TestLocalURLs(t *testing.T) {

	// Local resources we should never fetch
	tests := []string{"http://localhost/",
		"http://127.0.0.1/server-status",
		"https://localhost/",
		"https://127.0.127.127/",
		"https://0.0.0.0/",
		"http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key",
		"http://[fe80::1]:6379/",
	}

	var netClient = &http.Client{
		Transport: Transport(),
		Timeout:   5 * time.Second,
	}

	for _, url := range tests {

		// Prepare
		req, err := http.NewRequest("GET", url, nil)

		if err != nil {
			t.Fatalf("Unexpected error requesting %s %s", url, err.Error())
		}

		// Fetch
		_, err = netClient.Do(req)
		if err == nil {
			t.Fatalf("Expected error requesting %s - expected to be denied", url)
		}
		if !strings.Contains(err.Error(), "denied as local") {
			t.Fatalf("Received an error accessing %s, but not the expected one.  Got: %s", url, err.Error())
		}
	}
}

// Test fetching resources that are valid is OK
func TestRemoteURLs(t *testing.T) {

	// These are random-sites that are fine to access.
	tests := []string{"http://steve.fi/",
		"http://example.com",
		"https://news.bbc.co.uk/",
	}

	var netClient = &http.Client{
		Transport: Transport(),
		Timeout:   5 * time.Second,
	}

	for _, url := range tests {

		// Prepare
		req, err := http.NewRequest("GET", url, nil)

		if err != nil {
			t.Fatalf("Unexpected error requesting %s %s", url, err.Error())
		}

		// Fetch
		_, err = netClient.Do(req)
		if err != nil {
			t.Fatalf("Didn't expect error; %s - %s", url, err.Error())
		}
	}
}
