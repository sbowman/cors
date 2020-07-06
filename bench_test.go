package cors

import (
	"net/http"
	"testing"

	"github.com/valyala/fasthttp"
)

type FakeResponse struct {
	header http.Header
}

func (r FakeResponse) Header() http.Header {
	return r.header
}

func (r FakeResponse) WriteHeader(n int) {
}

func (r FakeResponse) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func BenchmarkWithout(b *testing.B) {
	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod(http.MethodGet)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testHandler(&ctx)
	}
}

func BenchmarkDefault(b *testing.B) {
	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("http://example.com/foo")
	ctx.Request.Header.Add("Origin", "somedomain.com")

	handler := Default().Handler(testHandler)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler(&ctx)
	}
}

func BenchmarkAllowedOrigin(b *testing.B) {
	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("http://example.com/foo")
	ctx.Request.Header.Add("Origin", "somedomain.com")

	c := New(Options{
		AllowedOrigins: []string{"somedomain.com"},
	})

	handler := c.Handler(testHandler)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler(&ctx)
	}
}

func BenchmarkPreflight(b *testing.B) {
	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("http://example.com/foo")
	ctx.Request.Header.Add("Access-Control-Request-Method", "GET")

	handler := Default().Handler(testHandler)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler(&ctx)
	}
}

func BenchmarkPreflightHeader(b *testing.B) {
	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("http://example.com/foo")
	ctx.Request.Header.Add("Access-Control-Request-Method", "GET")
	ctx.Request.Header.Add("Access-Control-Request-Headers", "Accept")

	handler := Default().Handler(testHandler)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler(&ctx)
	}
}
