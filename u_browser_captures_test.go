package tls

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
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

// writtenClientHello returns the first TLS record that a client with this
// preset writes to its connection, so a test compares what goes on the wire,
// record header included.
func writtenClientHello(t *testing.T, id ClientHelloID, serverName string) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	client := UClient(clientConn, &Config{ServerName: serverName}, id)
	if err := serverConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var handshakeErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		// No server answers, so this ends in an error once the pipe closes.
		// Closing the client end lets the read below fail at once when the
		// handshake stops before it has written the record.
		handshakeErr = client.Handshake()
		clientConn.Close()
	}()
	stop := func() {
		clientConn.Close()
		serverConn.Close()
		<-done
	}
	t.Cleanup(stop)
	read := func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(serverConn, b); err != nil {
			stop()
			t.Fatalf("no complete ClientHello record: read: %v, handshake: %v", err, handshakeErr)
		}
		return b
	}
	record := read(recordHeaderLen)
	return append(record, read(int(record[3])<<8|int(record[4]))...)
}

// wireExtensions lists a ClientHello's extensions in wire order, each as its
// normalized ID and body. chrome155ParseWire groups them by ID, which hides
// which of the two GREASE extensions carries which body.
func wireExtensions(t *testing.T, data []byte) []string {
	t.Helper()
	r := chrome155Reader{t, data, "ClientHello"}
	if len(data) > 0 && data[0] == byte(recordTypeHandshake) {
		r.take(3)
		r = chrome155Reader{t, r.vector(2), "ClientHello handshake"}
	}
	r.take(1)
	r = chrome155Reader{t, r.vector(3), "ClientHello body"}
	r.take(2 + 32)
	r.vector(1) // legacy session id
	r.vector(2) // cipher suites
	r.vector(1) // compression methods
	r = chrome155Reader{t, r.vector(2), "ClientHello extensions"}
	var out []string
	for len(r.b) > 0 {
		id := uint16(r.number(2))
		out = append(out, fmt.Sprintf("%#04x:%s", chrome155NormalizeGREASE(id), chrome155NormalizeExtension(t, id, r.vector(2))))
	}
	return out
}

// compareGREASELayout checks what normalizing GREASE values hides in a
// BoringSSL hello: the capture starts and ends with a GREASE extension, the
// generated hello has the same first and last extension, bodies included,
// and each uses one GREASE group in supported_groups and key_share.
func compareGREASELayout(t *testing.T, capture, generated []byte) {
	t.Helper()
	want, got := wireExtensions(t, capture), wireExtensions(t, generated)
	if len(want) == 0 || len(got) == 0 {
		t.Fatalf("no extensions: capture has %d, generated hello has %d", len(want), len(got))
	}
	grease := fmt.Sprintf("%#04x:", GREASE_PLACEHOLDER)
	if !strings.HasPrefix(want[0], grease) || !strings.HasPrefix(want[len(want)-1], grease) {
		t.Errorf("capture does not start and end with GREASE: %s, %s", want[0], want[len(want)-1])
	}
	if got[0] != want[0] || got[len(got)-1] != want[len(want)-1] {
		t.Errorf("first and last extension\n got: %s, %s\nwant: %s, %s", got[0], got[len(got)-1], want[0], want[len(want)-1])
	}
	for name, hello := range map[string][]byte{"capture": capture, "generated hello": generated} {
		_, _, raw := chrome155ParseWire(t, hello)
		groups, shares := raw[10], raw[51]
		if len(groups) < 4 || len(shares) < 4 || !isGREASEUint16(uint16(groups[2])<<8|uint16(groups[3])) || !bytes.Equal(groups[2:4], shares[2:4]) {
			t.Errorf("%s: key_share does not start with the supported_groups GREASE group", name)
		}
	}
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
	record := writtenClientHello(t, HelloFirefox_156, chrome155FixtureServerName(t, raw))
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
// suites, the same extensions with the same deterministic bodies, the same
// GREASE extensions first and last, and one GREASE group in supported_groups
// and key_share; the order between the GREASE extensions is shuffled in both.
func TestEdge157CapturedClientHello(t *testing.T) {
	fixture := captureFixture(t, "edge157_clienthello.hex")
	want, _, captured := chrome155ParseWire(t, fixture)
	client := chrome155Build(t, HelloEdge_157, chrome155FixtureServerName(t, captured), nil)
	got, _, _ := chrome155ParseWire(t, client.HandshakeState.Hello.Raw)
	chrome155CompareWire(t, want, got)
	compareGREASELayout(t, fixture, client.HandshakeState.Hello.Raw)
}

// The upstream Chrome 155 capture tests compare through chrome155ParseWire,
// which normalizes the GREASE layout away. This checks it for the preset and
// for the spec the Fingerprinter reads from the capture.
func TestChrome155CapturedGREASELayout(t *testing.T) {
	fixture := chrome155Fixture(t)
	_, _, captured := chrome155ParseWire(t, fixture)
	serverName := chrome155FixtureServerName(t, captured)
	fingerprinted, err := (&Fingerprinter{}).FingerprintClientHello(fixture)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("preset", func(t *testing.T) {
		client := chrome155Build(t, HelloChrome_155, serverName, nil)
		compareGREASELayout(t, fixture, client.HandshakeState.Hello.Raw)
	})
	t.Run("fingerprinter", func(t *testing.T) {
		client := chrome155Build(t, HelloCustom, serverName, fingerprinted)
		compareGREASELayout(t, fixture, client.HandshakeState.Hello.Raw)
	})
}
