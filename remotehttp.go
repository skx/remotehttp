// Package remotehttp is a minor wrapper around a http.Transport which
// will refuse to fetch local resources.
//
// This package is specifically designed to avoid security attacks which
// might result from making HTTP-requests with user-supplied URLs.
//
// A prime example of this happening would be a web-service which is designed
// to fetch a document then convert it to PDF.  If the user requests a URL
// such as `http://localhost/server-status` they would receive a pretty PDF
// version of private information to which they should not be able to access.
//
// Of course you must make sure that users don't request `file://`,
// `ftp://` and other resources, but this wrapper will allow you to easily
// ensure that people cannot access your AWS-metadata store, or any other
// "internal" resources.
package remotehttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// _isLocalIP tests whether the IP address to which we've connected
// is a local one.
//
// If the IP is local then an error is returned.
func _isLocalIP(ip string) error {
	IP := net.ParseIP(ip)

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
			return fmt.Errorf("ip address %s is denied as local", ip)
		}
	}

	return nil
}

// Transport is our exported http.Transport object.
//
// This is the sole interface to this library, and it is
// designed to automatically deny connections which have
// been established to "local" resources.
//
// You may modify the transport as you wish, once you've received
// it.  However note that the DialContext and DialTLS fields should
// not be modified, or our protection is removed.
func Transport() *http.Transport {
	return &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Connect
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}

			// See where we connected to.
			ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())

			// Make the check
			err = _isLocalIP(ip)
			if err != nil {
				return c, err
			}

			return c, err
		},
		DialTLS: func(network, addr string) (net.Conn, error) {

			// Connect
			c, err := tls.Dial(network, addr, &tls.Config{})
			if err != nil {
				return nil, err
			}

			// See where we connected to.
			ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())

			// Make the check
			err = _isLocalIP(ip)
			if err != nil {
				return c, err
			}

			// Continue
			err = c.Handshake()
			if err != nil {
				return c, err
			}

			return c, c.Handshake()
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
}
