package remotehttp

import (
	"net/http"
	"testing"
	"time"
)

func TestLocalURLs(t *testing.T) {

	// Local resources we should never fetch
	tests := []string{"http://localhost/",
		"http://127.0.0.1/server-status",
		"https://localhost/",
		"https://127.0.127.127/",
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
	}
}
