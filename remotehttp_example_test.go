package remotehttp

import (
	"fmt"
	"net/http"
	"time"
)

// Example shows how access to `http://localhost/server-status` is
// easily denied.
func Example() {

	// The URL we're fetching
	url := "http://localhost/server-status"

	transport := Transport

	// Make a HTTP-client with our transport.
	var netClient = &http.Client{
		Transport: transport,
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
		fmt.Printf("ERROR:%s\n", err.Error())
	}
	// Output:
	// ERROR:Get "http://localhost/server-status": ip address 127.0.0.1 is denied as local
}
