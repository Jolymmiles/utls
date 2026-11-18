package tls

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"strings"
	"testing"
	"testing/cryptotest"
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

// ShuffleChromeTLSExtensions permutes the movable extensions uniformly and
// leaves GREASE, padding and pre_shared_key where they were. Every swap
// index comes from crypto/rand, so a fixed crypto/rand source reproduces
// the order, and four movable extensions reach all 24 orders about equally
// often. A shuffle seeded once from crypto/rand, or a rotation, does not.
func TestShuffleChromeTLSExtensionsIsUniform(t *testing.T) {
	grease, padding := &UtlsGREASEExtension{}, &UtlsPaddingExtension{}
	base := []TLSExtension{
		grease,
		&SNIExtension{},
		&ALPNExtension{},
		padding,
		&StatusRequestExtension{},
		&SessionTicketExtension{},
		&FakePreSharedKeyExtension{},
	}
	movable := []int{1, 2, 4, 5}
	order := func(seed uint64) string {
		cryptotest.SetGlobalRandom(t, seed)
		exts := ShuffleChromeTLSExtensions(append([]TLSExtension(nil), base...))
		if exts[0] != grease || exts[3] != padding || exts[6] != base[6] {
			t.Fatalf("seed %d moved a fixed extension: %v", seed, exts)
		}
		var names []string
		for _, i := range movable {
			names = append(names, extName(exts[i]))
		}
		return strings.Join(names, ",")
	}
	const rounds = 2400
	counts := map[string]int{}
	for seed := range uint64(rounds) {
		counts[order(seed)]++
	}
	if len(counts) != 24 {
		t.Fatalf("%d orders of 4 movable extensions in %d hellos, want all 24: %v", len(counts), rounds, counts)
	}
	for o, n := range counts {
		if f := float64(n) / (rounds / 24); f < 0.6 || f > 1.4 {
			t.Errorf("order %s in %d of %d hellos, want about %d", o, n, rounds, rounds/24)
		}
	}
	if order(7) != order(7) {
		t.Error("the same crypto/rand source gave two orders")
	}
}

// Each swap draws its own value from crypto/rand. Sources that agree on
// their first 8 bytes and differ after them give different orders of
// Chrome's extensions; a math/rand source seeded from the first 8 bytes
// would give one order for all of them.
func TestShuffleChromeTLSExtensionsDrawsEverySwap(t *testing.T) {
	spec, err := UTLSIdToSpec(HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	saved := crand.Reader
	defer func() { crand.Reader = saved }()
	orders := map[string]bool{}
	for seed := range int64(20) {
		tail := mrand.New(mrand.NewSource(seed))
		crand.Reader = io.MultiReader(bytes.NewReader(make([]byte, 8)), tail)
		var names []string
		for _, ext := range ShuffleChromeTLSExtensions(append([]TLSExtension(nil), spec.Extensions...)) {
			names = append(names, extName(ext))
		}
		orders[strings.Join(names, ",")] = true
	}
	if len(orders) < 2 {
		t.Fatalf("20 crypto/rand sources that share their first 8 bytes gave %d order", len(orders))
	}
}

func extName(ext TLSExtension) string {
	if e, ok := ext.(*GenericExtension); ok {
		return fmt.Sprintf("generic %d", e.Id)
	}
	return fmt.Sprintf("%T", ext)
}
