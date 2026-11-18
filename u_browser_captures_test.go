package tls

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// captureFixture reads a captured ClientHello record from testdata.
func captureFixture(t *testing.T, name string) []byte {
	t.Helper()
	text, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.Join(strings.Fields(string(text)), ""))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// nssNormalizeExtension is chrome155NormalizeExtension for an NSS hello:
// Firefox's GREASE ECH has one payload length for a given server name, so
// the length is compared exactly; the config id, AEAD, enc and payload
// bytes are free.
func nssNormalizeExtension(t *testing.T, id uint16, body []byte) string {
	t.Helper()
	if id != 0xfe0d {
		return chrome155NormalizeExtension(t, id, body)
	}
	r := chrome155Reader{t, body, "encrypted_client_hello"}
	outer, kdf, aead := r.number(1), r.number(2), r.number(2)
	r.take(1) // random config_id
	enc, payload := r.vector(2), r.vector(2)
	r.end()
	// NSS picks AES-128-GCM or ChaCha20-Poly1305 for each hello; both
	// appear in Firefox captures, and the preset draws from the same two.
	if aead != 1 && aead != 3 {
		t.Fatalf("GREASE ECH AEAD %d, want AES-128-GCM or ChaCha20-Poly1305", aead)
	}
	return fmt.Sprintf("%d/%d/aead=1|3/enc=%d/payload=%d", outer, kdf, len(enc), len(payload))
}

type capturedHello struct {
	Version     uint16
	Ciphers     []uint16
	Compression []byte
	Order       []uint16
	Extensions  map[uint16]string
}

// parseNSSHello parses a ClientHello with its extensions in wire order.
func parseNSSHello(t *testing.T, data []byte) capturedHello {
	t.Helper()
	r := chrome155Reader{t, data, "record"}
	if r.number(1) != int(recordTypeHandshake) || r.number(2) != int(VersionTLS10) {
		t.Fatal("unexpected ClientHello TLS record header")
	}
	record := r.vector(2)
	r.end()
	r = chrome155Reader{t, record, "handshake"}
	if r.number(1) != 1 {
		t.Fatal("not a ClientHello")
	}
	body := r.vector(3)
	r.end()
	r = chrome155Reader{t, body, "ClientHello"}
	out := capturedHello{Version: uint16(r.number(2)), Extensions: map[uint16]string{}}
	r.take(32)
	r.vector(1) // legacy session id, random
	out.Ciphers = chrome155Uint16s(t, r.vector(2))
	out.Compression = bytes.Clone(r.vector(1))
	exts := chrome155Reader{t, r.vector(2), "extensions"}
	r.end()
	for len(exts.b) > 0 {
		id := uint16(exts.number(2))
		out.Order = append(out.Order, id)
		out.Extensions[id] = nssNormalizeExtension(t, id, exts.vector(2))
	}
	return out
}

// HelloFirefox_156 against a fresh Firefox 156.0.1 hello: the same cipher
// suites, extension order, record length and every extension body apart from
// key shares and the GREASE ECH bytes.
func TestFirefox156CapturedClientHello(t *testing.T) {
	fixture := captureFixture(t, "firefox156_clienthello.hex")
	want := parseNSSHello(t, fixture)
	_, _, raw := chrome155ParseWire(t, fixture)
	client := chrome155Build(t, HelloFirefox_156, chrome155FixtureServerName(t, raw), nil)
	record := append([]byte{byte(recordTypeHandshake), 3, 1, 0, 0}, client.HandshakeState.Hello.Raw...)
	record[3], record[4] = byte(len(client.HandshakeState.Hello.Raw)>>8), byte(len(client.HandshakeState.Hello.Raw))
	got := parseNSSHello(t, record)
	if !slices.Equal(got.Order, want.Order) {
		t.Errorf("extension order\n got: %v\nwant: %v", got.Order, want.Order)
	}
	if !reflect.DeepEqual(got, want) {
		for id, body := range want.Extensions {
			if got.Extensions[id] != body {
				t.Errorf("extension %d\n got: %s\nwant: %s", id, got.Extensions[id], body)
			}
		}
		if !slices.Equal(got.Ciphers, want.Ciphers) {
			t.Errorf("cipher suites\n got: %x\nwant: %x", got.Ciphers, want.Ciphers)
		}
		if got.Version != want.Version {
			t.Errorf("legacy version %#04x, want %#04x", got.Version, want.Version)
		}
		if !bytes.Equal(got.Compression, want.Compression) {
			t.Errorf("compression methods %x, want %x", got.Compression, want.Compression)
		}
	}
	if len(record) != len(fixture) {
		t.Errorf("record of %d bytes, want %d", len(record), len(fixture))
	}
}

// HelloEdge_157 against a fresh Edge 157.0.4341.60 hello: the same cipher
// suites, the same extensions with the same deterministic bodies, and GREASE
// first and last; the order between them is shuffled in both.
func TestEdge157CapturedClientHello(t *testing.T) {
	fixture := captureFixture(t, "edge157_clienthello.hex")
	want, wantOrder, raw := chrome155ParseWire(t, fixture)
	client := chrome155Build(t, HelloEdge_157, chrome155FixtureServerName(t, raw), nil)
	got, gotOrder, _ := chrome155ParseWire(t, client.HandshakeState.Hello.Raw)
	chrome155CompareWire(t, want, got)
	for name, order := range map[string][]uint16{"capture": wantOrder, "preset": gotOrder} {
		if order[0] != GREASE_PLACEHOLDER || order[len(order)-1] != GREASE_PLACEHOLDER {
			t.Errorf("%s: GREASE not first and last: %x", name, order)
		}
	}
}
