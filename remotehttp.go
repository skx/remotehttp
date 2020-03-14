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
	"strings"
	"time"
)

var (
	// Cached store of network/netmask to IP-range - IPv4
	ip4Ranges map[string]*net.IPNet

	// Cached store of network/netmask to IP-range - IPv6
	ip6Ranges map[string]*net.IPNet
)

// _isLocalIP tests whether the IP address to which we've connected is a local one.
func _isLocalIP(IP net.IP) error {

	localIP4 := []string{
		"10.0.0.0/8",         // RFC1918
		"100.64.0.0/10",      // RFC 6598
		"127.0.0.0/8",        // IPv4 loopback
		"169.254.0.0/16",     // RFC3927 link-local
		"172.16.0.0/12",      // RFC1918
		"192.0.0.0/24",       // RFC 5736
		"192.0.2.0/24",       // RFC 5737
		"192.168.0.0/16",     // RFC1918
		"192.18.0.0/15",      // RFC 2544
		"192.88.99.0/24",     // RFC 3068
		"198.51.100.0/24",    //
		"203.0.113.0/24",     //
		"224.0.0.0/4",        // RFC 3171
		"255.255.255.255/32", // RFC 919 Section 7
	}
	localIP6 := []string{
		"::/128",        // RFC 4291: Unspecified Address
		"100::/64",      // RFC 6666: Discard Address Block
		"2001:2::/48",   // RFC 5180: Benchmarking
		"2001::/23",     // RFC 2928: IETF Protocol Assignments
		"2001::/32",     // RFC 4380: TEREDO
		"2001:db8::/32", // RFC 3849: Documentation
		"::1/128",       // RFC 4291: Loopback Address
		"fc00::/7",      // RFC 4193: Unique-Local
		"fe80::/10",     // RFC 4291: Section 2.5.6 Link-Scoped Unicast
		"ff00::/8",      // RFC 4291: Section 2.7
	}

	// If we've not already parsed our CIDR ranges into maps then do so.
	//
	// This saves time if we're going to test multiple hostnames/URIs
	// with this same object.
	if len(ip4Ranges) == 0 {

		// Create map
		ip4Ranges = make(map[string]*net.IPNet)
		ip6Ranges = make(map[string]*net.IPNet)

		// Join our ranges.
		tmp := localIP4
		tmp = append(tmp, localIP6...)

		// For each one.
		for _, entry := range tmp {

			// Parse
			_, block, err := net.ParseCIDR(entry)
			if err != nil {
				return err
			}

			// Record in the protocol-specific range
			if strings.Contains(entry, ":") {
				ip6Ranges[entry] = block
			} else {
				ip4Ranges[entry] = block
			}
		}
	}

	// The map we're testing from
	testMap := ip4Ranges

	// Are we testing an IPv6 address?
	if strings.Contains(IP.String(), ":") {
		testMap = ip6Ranges
	}

	// Loop over the appropriate map and test for inclusion
	for _, block := range testMap {
		if block.Contains(IP) {
			return fmt.Errorf("ip address %s is denied as local", IP)
		}
	}

	// Not found.
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
func _checker(ctx context.Context, dialler *net.Dialer, network, addr string) (net.Conn, error) {

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

		// If the IP was bad we'll have terminated already
		//
		// So if we managed to get here we found (at least) 1 valid IP.
		//
		// We'll walk over each IP; so if `example.com` resolves
		// to 1.2.3.4 and 1.2.3.6 we'll try each of them in turn.
		//
		// Importantly here we're using `target` to specify the resolved
		// address we've confirmed is safe.
		//
		con, err := dialler.DialContext(ctx, network, target)
		if err == nil {
			// No error?  Then we're good and we return the
			// connection to the caller.
			return con, err
		}
	}

	//
	// If we got here then:
	//
	//  a) We didn't resolve the host.
	//
	//  b) We resolved the host, but connecting to any (valid) IP
	//     failed
	if len(ips) < 1 {
		return nil, fmt.Errorf("failed to resolve host from %s", addr)
	}

	// Failed to connect
	return nil, fmt.Errorf("failed to connect to %s", addr)
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
			return (_checker(ctx, dialler, network, addr))
		},

		// Setup a simple timeout
		TLSHandshakeTimeout: 5 * time.Second,

		// Setup a simple timeout
		ResponseHeaderTimeout: 5 * time.Second,
	}
}
