# Xray-core fork of uTLS

This branch is `github.com/refraction-networking/utls` at `a13c59ffe98b`
("Fix UQUICConn Close after cancellation and preset transport parameters"), the version Xray-core pins, plus the changes
below. Xray-core uses it through a `replace` in its `go.mod`; the module path
stays `github.com/refraction-networking/utls`.

## Changes

- Keep the private keys of the classical key shares after the first, by
  group (`KeySharePrivateKeys.EcdheFallback`), and derive the shared secret
  with the one the server selected
  (`ecdhKeyExchange.clientSharedSecretChooseEcdhe`). Upstream keeps
  the first only, so a Firefox fingerprint (key shares X25519, P-256) fails
  with "tls: invalid server key share" against a server that selects P-256
  (refraction-networking/utls#402). Backport of
  refraction-networking/utls#416. Covered by
  `TestSecondaryKeyShareSelectedByServer`.
- `HelloFirefox_156` (`u_common.go`, `u_parrots.go`), which becomes
  `HelloFirefox_Auto`: Firefox dropped the ECDSA CBC suites and FFDHE
  groups of `HelloFirefox_148` and sends session_ticket and
  psk_key_exchange_modes. Against a fresh Firefox 156.0.1 hello
  (`testdata/firefox156_clienthello.hex`) it matches the cipher suites, the
  extension order, the record length and every extension body except the
  key shares and the GREASE ECH config id, AEAD, enc and payload bytes.
  The preset models a fresh hello only: on a TLS 1.3 resumption Firefox
  drops session_ticket and sends a longer ECH extension (378 and 570
  bytes in our Firefox 160 and 156 captures), which the preset does not.
  Two limits on the GREASE ECH, as in `HelloFirefox_148`:
  - its `enc` is a real X25519 public key, so the top bit of its last byte
    is always clear, where NSS writes 32 pseudorandom bytes
    (`tls13_MaybeGreaseEch`);
  - the extension is fixed at 282 bytes. NSS pads the server name to 100
    bytes and rounds up to 32: Firefox 156 sent 282 bytes for an
    86-character name and 314 for a 138-character one, and no length
    between them was measured.

  Covered by `TestFirefox156CapturedClientHello`, `TestFirefox156Spec`,
  `TestFirefox156Handshakes` and `TestSecondaryKeyShareSelectedByServer`.
- `HelloEdge_157` (`u_common.go`, `u_parrots.go`), which becomes
  `HelloEdge_Auto` in place of Edge 85: Chrome 155's hello without
  trust_anchors. Against a fresh Edge 157.0.4341.60 hello
  (`testdata/edge157_clienthello.hex`) it matches the cipher suites, the
  extension multiset with every deterministic body, and GREASE first and
  last; the order between them is shuffled in both. It rests on one Linux
  build. Its floor is TLS 1.2, where Edge 85 offered TLS 1.0 and 1.1.
  Covered by `TestEdge157CapturedClientHello` and
  `TestEdge157IsChrome155WithoutTrustAnchors`.
- `HelloSafari_26_3`, which is `HelloSafari_Auto`, keeps upstream's spec and
  gains a fixture. Against a fresh Safari 27.3 hello
  (`testdata/safari27_clienthello.hex`) it matches the record header and
  length, the cipher suites, and the extensions in order with every body,
  apart from GREASE values and key share bytes. That is what the fixture
  shows; no Safari 26.3 capture is kept here to compare the two versions.
  It rests on one macOS build and loopback servers. Covered by
  `TestSafari26CapturedClientHello`.
- `ShuffleChromeTLSExtensions` (`u_parrots.go`) permutes the movable
  extensions uniformly among themselves and draws every swap index from
  `crypto/rand`, as BoringSSL draws an independent value per swap. Upstream
  skips every swap that touches GREASE, padding or pre_shared_key, which
  left each extension in its source slot in about 11% of hellos (SNI first
  in 11% of Chrome hellos against the uniform 5.9%), and seeds one
  `math/rand` source per call, which reaches at most 2^31-1 of the 17!
  orders of Chrome 155's movable extensions. A fixed `crypto/rand` source
  (`cryptotest.SetGlobalRandom`) still reproduces the order. Covered by
  `TestShuffleChromeTLSExtensionsIsUniform` and
  `TestShuffleChromeTLSExtensionsDrawsEverySwap`.

## Updating

Drop a change once upstream ships it, rebase the rest on the new upstream
commit, and run `go test ./...` here and the uTLS tests in Xray-core
(`transport/internet/tls`, `transport/internet/reality`).
