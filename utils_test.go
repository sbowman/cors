package cors

import (
	"strings"
	"testing"
)

func TestWildcard(t *testing.T) {
	w := wildcard{[]byte("foo"), []byte("bar")}
	if !w.match([]byte("foobar")) {
		t.Error("foo*bar should match foobar")
	}
	if !w.match([]byte("foobazbar")) {
		t.Error("foo*bar should match foobazbar")
	}
	if w.match([]byte("foobaz")) {
		t.Error("foo*bar should not match foobaz")
	}

	w = wildcard{[]byte("foo"), []byte("oof")}
	if w.match([]byte("foof")) {
		t.Error("foo*oof should not match foof")
	}
}

func TestConvert(t *testing.T) {
	s := convert([]string{"A", "b", "C"}, strings.ToLower)
	e := []string{"a", "b", "c"}
	if s[0] != e[0] || s[1] != e[1] || s[2] != e[2] {
		t.Errorf("%v != %v", s, e)
	}
}

func TestParseHeaderList(t *testing.T) {
	h := parseHeaderList([]byte("header, second-header, THIRD-HEADER, Numb3r3d-H34d3r"))
	e := []string{"Header", "Second-Header", "Third-Header", "Numb3r3d-H34d3r"}
	if h[0] != e[0] || h[1] != e[1] || h[2] != e[2] {
		t.Errorf("%v != %v", h, e)
	}
}

func TestParseHeaderListEmpty(t *testing.T) {
	if len(parseHeaderList(nil)) != 0 {
		t.Error("should be empty slice")
	}
	if len(parseHeaderList([]byte(" , "))) != 0 {
		t.Error("should be empty slice")
	}
}

func BenchmarkParseHeaderList(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		parseHeaderList([]byte("header, second-header, THIRD-HEADER"))
	}
}

func BenchmarkParseHeaderListSingle(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		parseHeaderList([]byte("header"))
	}
}

func BenchmarkParseHeaderListNormalized(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		parseHeaderList([]byte("Header1, Header2, Third-Header"))
	}
}

func BenchmarkWildcard(b *testing.B) {
	w := wildcard{[]byte("foo"), []byte("bar")}
	b.Run("match", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			w.match([]byte("foobazbar"))
		}
	})
	b.Run("too short", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			w.match([]byte("fobar"))
		}
	})
}
