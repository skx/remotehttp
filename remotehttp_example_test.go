package remotehttp

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Example shows how access to `http://localhost/server-status` is
// easily denied.
func Example() {

	// The URL we're fetching
	url := "http://localhost/server-status"

	// Make a HTTP-client with our transport.
	var netClient = &http.Client{
		Transport: Transport(),
		Timeout:   5 * time.Second,
	}

	// Create a request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("error preparing HTTP-request %s %s", url, err.Error())
		return
	}

	// Make the (GET) request
	_, err = netClient.Do(req)
	if err != nil {

		//
		// Remove "::1" and "127.0.0.1" in our error-message.
		//
		// Because we could get two different errors:
		//
		//    ip address ::1 is denied as local
		//    ip address 127.0.0.1 is denied as local
		//
		// We want to be stable, and work regardless of what the
		// local testing-system returns.
		//
		out := err.Error()
		out = strings.ReplaceAll(out, "127.0.0.1 ", "")
		out = strings.ReplaceAll(out, "::1 ", "")

		fmt.Printf("ERROR:%s\n", out)
	}
	// Output:
	// ERROR:Get "http://localhost/server-status": ip address is denied as local
}
