package tls

import (
	"fmt"
	"testing"
)

// Firefox 156 is what "firefox" parrots: no ECDSA CBC suites or FFDHE
// groups, and session_ticket and psk_key_exchange_modes, as in Firefox 160
// captures.
func TestFirefox156Spec(t *testing.T) {
	if HelloFirefox_Auto != HelloFirefox_156 {
		t.Fatalf("HelloFirefox_Auto = %s, want Firefox 156", HelloFirefox_Auto.Str())
	}
	spec, err := UTLSIdToSpec(HelloFirefox_156)
	if err != nil {
		t.Fatal(err)
	}
	for _, suite := range spec.CipherSuites {
		switch suite {
		case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
			t.Errorf("offers ECDSA CBC suite %#04x, which Firefox dropped", suite)
		}
	}
	var sessionTicket, pskModes bool
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *SupportedCurvesExtension:
			for _, curve := range e.Curves {
				if curve >= FakeCurveFFDHE2048 && curve <= 0x0104 {
					t.Errorf("offers FFDHE group %#04x, which Firefox dropped", curve)
				}
			}
		case *SessionTicketExtension:
			sessionTicket = true
		case *PSKKeyExchangeModesExtension:
			pskModes = true
		}
	}
	if !sessionTicket || !pskModes {
		t.Errorf("session_ticket %v, psk_key_exchange_modes %v; Firefox sends both", sessionTicket, pskModes)
	}
}

// A Firefox 156 hello completes TLS 1.3 and TLS 1.2 handshakes.
func TestFirefox156Handshakes(t *testing.T) {
	for _, maxVersion := range []uint16{VersionTLS13, VersionTLS12} {
		serverConfig := testConfigServer.Clone()
		serverConfig.MaxVersion = maxVersion
		clientConfig := testConfigClient.Clone()
		clientConfig.ServerName = "example.com"
		clientConfig.InsecureSkipVerify = true

		clientConn, serverConn := localPipe(t)
		server := Server(serverConn, serverConfig)
		client := UClient(clientConn, clientConfig, HelloFirefox_156)
		serverErr := make(chan error, 1)
		go func() { serverErr <- server.Handshake() }()
		if err := client.Handshake(); err != nil {
			t.Fatalf("TLS %#04x: client handshake: %v", maxVersion, err)
		}
		if err := <-serverErr; err != nil {
			t.Fatalf("TLS %#04x: server handshake: %v", maxVersion, err)
		}
		if v := client.ConnectionState().Version; v != maxVersion {
			t.Fatalf("negotiated %#04x, want %#04x", v, maxVersion)
		}
		client.Close()
		server.Close()
	}
}

// ShuffleChromeTLSExtensions permutes the movable extensions uniformly: each
// comes first about equally often. Skipping the swaps that touch GREASE left
// the extensions next to it in place twice as often.
func TestShuffleChromeTLSExtensionsIsUniform(t *testing.T) {
	spec, err := UTLSIdToSpec(HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	base := spec.Extensions
	var movable int
	firstMovable := -1
	for i, ext := range base {
		switch ext.(type) {
		case *UtlsGREASEExtension, *UtlsPaddingExtension, PreSharedKeyExtension:
		default:
			movable++
			if firstMovable < 0 {
				firstMovable = i
			}
		}
	}
	const rounds = 20000
	counts := map[string]int{}
	for range rounds {
		exts := ShuffleChromeTLSExtensions(append([]TLSExtension(nil), base...))
		counts[extName(exts[firstMovable])]++
	}
	want := float64(rounds) / float64(movable)
	for name, n := range counts {
		if f := float64(n) / want; f < 0.75 || f > 1.25 {
			t.Errorf("%s first in %d of %d hellos, want about %.0f", name, n, rounds, want)
		}
	}
	if len(counts) != movable {
		t.Errorf("%d extensions came first, want all %d movable", len(counts), movable)
	}
}

func extName(ext TLSExtension) string {
	if e, ok := ext.(*GenericExtension); ok {
		return fmt.Sprintf("generic %d", e.Id)
	}
	return fmt.Sprintf("%T", ext)
}
