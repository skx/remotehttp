// Package remotehttp is a minor wrapper around a http.Transport which will refuse to fetch local resources.
//
// This package is specifically designed to avoid security attacks which might result from making HTTP-requests with
// user-supplied URLs.
//
// A prime example of this happening would be a web-service which is designed to fetch a document then convert it to PDF.
// If the user requests a URL such as `http://localhost/server-status` they would receive a PDF file of private information
// which they should not have been able to access.
//
// Of course you must make sure that users don't request `file://`, `ftp://` and other resources, but this wrapper will
// allow you to easily ensure that people cannot access your AWS-metadata store, or any other "internal" resources.
package remotehttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// _isLocalIP tests whether the IP address to which we've connected is a local one.
func _isLocalIP(IP net.IP) error {

	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}

		if block.Contains(IP) {
			return fmt.Errorf("ip address %s is denied as local", IP)
		}
	}

	return nil
}

// _checker is the thing that makes our check.
//
// This function handles things as you would expect:
//
// * Resolve the target to an IP
//
// * If the IP is blacklisted abort
//
// * Otherwise update the destination to which we'll connect, such
//   that we use the returned IP address explicitly.  This ensures we don't
//   have a time-of-check-time-of-use-race
//
func _checker(dialler *net.Dialer, ctx context.Context, network, addr string) (net.Conn, error) {

	// Split the address into host/port
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// Resolve the given host to an IP
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	// Now check the resolved IP against our blacklist
	//
	// We'll want to rewrite the target so that we
	// explicitly connect to this resolved IP too,
	// rather than using the DNS name - which would
	// be racy.
	target := ""

	// For each IP we received
	for _, ip := range ips {

		// Is it blacklisted?  Then abort
		err = _isLocalIP(ip)
		if err != nil {
			return nil, err
		}

		// Set the connection-target to the resolved address.
		if ip.To4() != nil {
			target = fmt.Sprintf("%s:%s", ip, port)
		}
		if ip.To16() != nil && ip.To4() == nil {
			target = fmt.Sprintf("[%s]:%s", ip, port)
		}
	}

	// If the IP was bad we'll have terminated already
	//
	// If we got here we found (at least) one valid IP.
	//
	// NOTE: We'll essentially use the "last" DNS entry which was
	// returned, as we update the `target` each time we process
	// a DNS result.
	//
	// So if `example.com` resolves to 1.2.3.4 and 1.2.3.6 we'll
	// be using the second version.
	//
	// TODO: Perhaps randomize results?
	//
	// Importantly here we're using `target` to specify the resolved
	// address we've confirmed is safe.
	return dialler.DialContext(ctx, network, target)
}

// Transport returns our wrapped http.Transport object.
//
// This function is the sole interface to this library, which is designed to automatically deny connections to
// "local" resources.
//
// You may modify the transport as you wish, once you've received it.  However note that the `DialContext` function should
// not be changed, or our protection is removed.
func Transport() *http.Transport {

	// Setup a timeout in our dialler; though the user could change this.
	dialler := &net.Dialer{
		DualStack: true,
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Create a transport with the suitable handlers.
	return &http.Transport{

		// Setup the dialler.
		Dial: dialler.Dial,

		// Setup the connection helper
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (_checker(dialler, ctx, network, addr))
		},

		// Setup a simple timeout
		TLSHandshakeTimeout: 5 * time.Second,

		// Setup a simple timeout
		ResponseHeaderTimeout: 5 * time.Second,
	}
}
