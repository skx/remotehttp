[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://pkg.go.dev/github.com/skx/remotehttp)
[![Go Report Card](https://goreportcard.com/badge/github.com/skx/remotehttp)](https://goreportcard.com/report/github.com/skx/remotehttp)
[![license](https://img.shields.io/github/license/skx/remotehttp.svg)](https://github.com/skx/remotehttp/blob/master/LICENSE)

# remotehttp

This repository contains a trivial helper for making secure HTTP-requests with golang.



# The Problem

Imagine you have a service to which users to submit tasks containing references to remote objects (HTTP-URLs).

* For example you might allow users to enter the location of a HTML document.
* Your service fetches that remote resource, then converts it to PDF, or similar.
* The results are then shown to the user.

Now imagine what happens if the user supplies URLs such as these, as input to your service:

* http://localhost/server-status
* http://169.254.169.254/latest/meta-data/

This package allows you to __prevent__ these inputs from being processed, easily.



## Using It

Sample usage can be found in [remotehttp_example_test.go](remotehttp_example_test.go).


## Other considerations

This wrapper-library only considers the case of `http` and `https` schemas; if you're accepting URIs of your own you should absolutely sanity-check you've not been given something with a `file://`, or `ftp://` prefix (and more!)

Other things you'll want to consider:

* Resource limits such as timeout-handling.
* Resource limits such as whether to follow redirections, and if so how many.

Steve
