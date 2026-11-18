package tls

import (
	"reflect"
	"testing"
)

// Edge 157 (captured on Linux, 157.0.4341.60) sends Chrome 155's
// ClientHello without the trust_anchors extension.
func TestEdge157IsChrome155WithoutTrustAnchors(t *testing.T) {
	edge, err := UTLSIdToSpec(HelloEdge_157)
	if err != nil {
		t.Fatal(err)
	}
	chrome, err := UTLSIdToSpec(HelloChrome_155)
	if err != nil {
		t.Fatal(err)
	}
	types := func(spec ClientHelloSpec) map[string]int {
		m := map[string]int{}
		for _, e := range spec.Extensions {
			m[reflect.TypeOf(e).String()]++
		}
		return m
	}
	want := types(chrome)
	delete(want, "*tls.TrustAnchorsExtension")
	if got := types(edge); !reflect.DeepEqual(got, want) {
		t.Fatalf("Edge 157 extensions %v, want %v", got, want)
	}
	if !reflect.DeepEqual(edge.CipherSuites, chrome.CipherSuites) {
		t.Fatal("Edge 157 offers Chrome 155's cipher suites")
	}
	if HelloEdge_Auto != HelloEdge_157 {
		t.Fatal("HelloEdge_Auto is Edge 157")
	}
}
