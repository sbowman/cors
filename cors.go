/*
Package cors is net/http handler to handle CORS related requests
as defined by http://www.w3.org/TR/cors/

You can configure it by passing an option struct to cors.New:

    c := cors.New(cors.Options{
        AllowedOrigins:   []string{"foo.com"},
        AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodDelete},
        AllowCredentials: true,
    })

Then insert the handler in the chain:

    handler = c.Handler(handler)

See Options documentation for more options.

The resulting handler is a standard net/http handler.
*/
package cors

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/valyala/fasthttp"
)

// Options is a configuration container to setup the CORS middleware.
type Options struct {
	// AllowedOrigins is a list of origins a cross-domain request can be executed from.
	// If the special "*" value is present in the list, all origins will be allowed.
	// An origin may contain a wildcard (*) to replace 0 or more characters
	// (i.e.: http://*.domain.com). Usage of wildcards implies a small performance penalty.
	// Only one wildcard can be used per origin.
	// Default value is ["*"]
	AllowedOrigins []string
	// AllowOriginFunc is a custom function to validate the origin. It take the origin
	// as argument and returns true if allowed or false otherwise. If this option is
	// set, the content of AllowedOrigins is ignored.
	AllowOriginFunc func(origin []byte) bool
	// AllowOriginRequestFunc is a custom function to validate the origin. It takes the HTTP Request object and the origin as
	// argument and returns true if allowed or false otherwise. If this option is set, the content of `AllowedOrigins`
	// and `AllowOriginFunc` is ignored.
	AllowOriginRequestFunc func(ctx *fasthttp.RequestCtx, origin []byte) bool
	// AllowedMethods is a list of methods the client is allowed to use with
	// cross-domain requests. Default value is simple methods (HEAD, GET and POST).
	AllowedMethods []string
	// AllowedHeaders is list of non simple headers the client is allowed to use with
	// cross-domain requests.
	// If the special "*" value is present in the list, all headers will be allowed.
	// Default value is [] but "Origin" is always appended to the list.
	AllowedHeaders []string
	// ExposedHeaders indicates which headers are safe to expose to the API of a CORS
	// API specification
	ExposedHeaders []string
	// MaxAge indicates how long (in seconds) the results of a preflight request
	// can be cached
	MaxAge int
	// AllowCredentials indicates whether the request can include user credentials like
	// cookies, HTTP authentication or client side SSL certificates.
	AllowCredentials bool
	// OptionsPassthrough instructs preflight to let other potential next handlers to
	// process the OPTIONS method. Turn this on if your application handles OPTIONS.
	OptionsPassthrough bool
	// Debugging flag adds additional output to debug server side CORS issues
	Debug bool
}

// Logger generic interface for logger
type Logger interface {
	Printf(string, ...interface{})
}

// Cors http handler
type Cors struct {
	// Debug logger
	Log Logger
	// Normalized list of plain allowed origins
	allowedOrigins [][]byte
	// List of allowed origins containing wildcards
	allowedWOrigins []wildcard
	// Optional origin validator function
	allowOriginFunc func(origin []byte) bool
	// Optional origin validator (with request) function
	allowOriginRequestFunc func(ctx *fasthttp.RequestCtx, origin []byte) bool
	// Normalized list of allowed headers
	allowedHeaders []string
	// Normalized list of allowed methods
	allowedMethods []string
	// Normalized list of exposed headers
	exposedHeaders []string
	maxAge         int
	// Set to true when allowed origins contains a "*"
	allowedOriginsAll bool
	// Set to true when allowed headers contains a "*"
	allowedHeadersAll bool
	allowCredentials  bool
	optionPassthrough bool
}

// New creates a new Cors handler with the provided options.
func New(options Options) *Cors {
	c := &Cors{
		exposedHeaders:         convert(options.ExposedHeaders, http.CanonicalHeaderKey),
		allowOriginFunc:        options.AllowOriginFunc,
		allowOriginRequestFunc: options.AllowOriginRequestFunc,
		allowCredentials:       options.AllowCredentials,
		maxAge:                 options.MaxAge,
		optionPassthrough:      options.OptionsPassthrough,
	}
	if options.Debug && c.Log == nil {
		c.Log = log.New(os.Stdout, "[cors] ", log.LstdFlags)
	}

	// Normalize options
	// Note: for origins and methods matching, the spec requires a case-sensitive matching.
	// As it may error prone, we chose to ignore the spec here.

	// Allowed Origins
	if len(options.AllowedOrigins) == 0 {
		if options.AllowOriginFunc == nil && options.AllowOriginRequestFunc == nil {
			// Default is all origins
			c.allowedOriginsAll = true
		}
	} else {
		c.allowedOrigins = [][]byte{}
		c.allowedWOrigins = []wildcard{}
		for _, origin := range options.AllowedOrigins {
			// Normalize
			origin = strings.ToLower(origin)
			if origin == "*" {
				// If "*" is present in the list, turn the whole list into a match all
				c.allowedOriginsAll = true
				c.allowedOrigins = nil
				c.allowedWOrigins = nil
				break
			} else if i := strings.IndexByte(origin, '*'); i >= 0 {
				// Split the origin in two: start and end string without the *
				w := wildcard{[]byte(origin[0:i]), []byte(origin[i+1:])}
				c.allowedWOrigins = append(c.allowedWOrigins, w)
			} else {
				c.allowedOrigins = append(c.allowedOrigins, []byte(origin))
			}
		}
	}

	// Allowed Headers
	if len(options.AllowedHeaders) == 0 {
		// Use sensible defaults
		c.allowedHeaders = []string{"Origin", "Accept", "Content-Type", "X-Requested-With"}
	} else {
		// Origin is always appended as some browsers will always request for this header at preflight
		c.allowedHeaders = convert(append(options.AllowedHeaders, "Origin"), http.CanonicalHeaderKey)
		for _, h := range options.AllowedHeaders {
			if h == "*" {
				c.allowedHeadersAll = true
				c.allowedHeaders = nil
				break
			}
		}
	}

	// Allowed Methods
	if len(options.AllowedMethods) == 0 {
		// Default is spec's "simple" methods
		c.allowedMethods = []string{http.MethodGet, http.MethodPost, http.MethodHead}
	} else {
		c.allowedMethods = convert(options.AllowedMethods, strings.ToUpper)
	}

	return c
}

// Default creates a new Cors handler with default options.
func Default() *Cors {
	return New(Options{})
}

// AllowAll create a new Cors handler with permissive configuration allowing all
// origins with all standard methods with any header and credentials.
func AllowAll() *Cors {
	return New(Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
		},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: false,
	})
}

// Handler apply the CORS specification on the request, and add relevant CORS headers
// as necessary.
func (c *Cors) Handler(h fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if ctx.IsOptions() && len(ctx.Request.Header.Peek("Access-Control-Request-Method")) != 0 {
			c.logf("Handler: Preflight request")
			c.handlePreflight(ctx)
			// Preflight requests are standalone and should stop the chain as some other
			// middleware may not handle OPTIONS requests correctly. One typical example
			// is authentication middleware ; OPTIONS requests won't carry authentication
			// headers (see #1)
			if c.optionPassthrough {
				h(ctx)
				return
			}

			ctx.SetStatusCode(http.StatusNoContent)
			return
		}

		c.logf("Handler: Actual request")
		c.handleActualRequest(ctx)
		h(ctx)
	}
}

// handlePreflight handles pre-flight CORS requests
func (c *Cors) handlePreflight(ctx *fasthttp.RequestCtx) {
	headers := &ctx.Response.Header
	origin := ctx.Request.Header.Peek("Origin")

	if !ctx.IsOptions() {
		c.logf("  Preflight aborted: %s!=OPTIONS", string(ctx.Request.Header.Method()))
		return
	}

	// Always set Vary headers
	// see https://github.com/rs/cors/issues/10,
	//     https://github.com/rs/cors/commit/dbdca4d95feaa7511a46e6f1efb3b3aa505bc43f#commitcomment-12352001
	headers.Add("Vary", "Origin")
	headers.Add("Vary", "Access-Control-Request-Method")
	headers.Add("Vary", "Access-Control-Request-Headers")

	if len(origin) == 0 {
		c.logf("  Preflight aborted: empty origin")
		return
	}

	if !c.isOriginAllowed(ctx, origin) {
		c.logf("  Preflight aborted: origin '%s' not allowed", origin)
		return
	}

	reqMethod := ctx.Request.Header.Peek("Access-Control-Request-Method")
	if !c.isMethodAllowed(reqMethod) {
		c.logf("  Preflight aborted: method '%s' not allowed", reqMethod)
		return
	}

	reqHeaders := parseHeaderList(ctx.Request.Header.Peek("Access-Control-Request-Headers"))
	if !c.areHeadersAllowed(reqHeaders) {
		c.logf("  Preflight aborted: headers '%v' not allowed", reqHeaders)
		return
	}

	if c.allowedOriginsAll {
		headers.Set("Access-Control-Allow-Origin", "*")
	} else {
		headers.SetBytesV("Access-Control-Allow-Origin", origin)
	}

	// Spec says: Since the list of methods can be unbounded, simply returning the method indicated
	// by Access-Control-Request-Method (if supported) can be enough
	headers.SetBytesV("Access-Control-Allow-Methods", bytes.ToUpper(reqMethod))
	if len(reqHeaders) > 0 {

		// Spec says: Since the list of headers can be unbounded, simply returning supported headers
		// from Access-Control-Request-Headers can be enough
		headers.Set("Access-Control-Allow-Headers", strings.Join(reqHeaders, ", "))
	}

	if c.allowCredentials {
		headers.Set("Access-Control-Allow-Credentials", "true")
	}

	if c.maxAge > 0 {
		headers.Set("Access-Control-Max-Age", strconv.Itoa(c.maxAge))
	}

	c.logf("  Preflight response headers: %v", headers)
}

// handleActualRequest handles simple cross-origin requests, actual request or redirects
func (c *Cors) handleActualRequest(ctx *fasthttp.RequestCtx) {
	headers := &ctx.Response.Header
	origin := ctx.Request.Header.Peek("Origin")

	// Always set Vary, see https://github.com/rs/cors/issues/10
	headers.Add("Vary", "Origin")
	if len(origin) == 0 {
		c.logf("  Actual request no headers added: missing origin")
		return
	}

	if !c.isOriginAllowed(ctx, origin) {
		c.logf("  Actual request no headers added: origin '%s' not allowed", origin)
		return
	}

	// Note that spec does define a way to specifically disallow a simple method like GET or
	// POST. Access-Control-Allow-Methods is only used for pre-flight requests and the
	// spec doesn't instruct to check the allowed methods for simple cross-origin requests.
	// We think it's a nice feature to be able to have control on those methods though.
	if !c.isMethodAllowed(ctx.Request.Header.Method()) {
		c.logf("  Actual request no headers added: method '%s' not allowed", string(ctx.Request.Header.Method()))
		return
	}

	if c.allowedOriginsAll {
		headers.Set("Access-Control-Allow-Origin", "*")
	} else {
		headers.SetBytesV("Access-Control-Allow-Origin", origin)
	}

	if len(c.exposedHeaders) > 0 {
		headers.Set("Access-Control-Expose-Headers", strings.Join(c.exposedHeaders, ", "))
	}

	if c.allowCredentials {
		headers.Set("Access-Control-Allow-Credentials", "true")
	}

	c.logf("  Actual response added headers: %v", headers)
}

// convenience method. checks if a logger is set.
func (c *Cors) logf(format string, a ...interface{}) {
	if c.Log != nil {
		c.Log.Printf(format, a...)
	}
}

// isOriginAllowed checks if a given origin is allowed to perform cross-domain requests
// on the endpoint
func (c *Cors) isOriginAllowed(ctx *fasthttp.RequestCtx, origin []byte) bool {
	if c.allowOriginRequestFunc != nil {
		return c.allowOriginRequestFunc(ctx, origin)
	}
	if c.allowOriginFunc != nil {
		return c.allowOriginFunc(origin)
	}
	if c.allowedOriginsAll {
		return true
	}
	origin = bytes.ToLower(origin)
	for _, o := range c.allowedOrigins {
		if bytes.Equal(o, origin) {
			return true
		}
	}
	for _, w := range c.allowedWOrigins {
		if w.match(origin) {
			return true
		}
	}
	return false
}

// isMethodAllowed checks if a given method can be used as part of a cross-domain request
// on the endpoint
func (c *Cors) isMethodAllowed(method []byte) bool {
	if len(c.allowedMethods) == 0 {
		// If no method allowed, always return false, even for preflight request
		return false
	}

	method = bytes.ToUpper(method)

	if string(method) == http.MethodOptions {
		// Always allow preflight requests
		return true
	}
	for _, m := range c.allowedMethods {
		if m == string(method) {
			return true
		}
	}
	return false
}

// areHeadersAllowed checks if a given list of headers are allowed to used within
// a cross-domain request.
func (c *Cors) areHeadersAllowed(requestedHeaders []string) bool {
	if c.allowedHeadersAll || len(requestedHeaders) == 0 {
		return true
	}
	for _, header := range requestedHeaders {
		header = http.CanonicalHeaderKey(header)
		found := false
		for _, h := range c.allowedHeaders {
			if h == header {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
