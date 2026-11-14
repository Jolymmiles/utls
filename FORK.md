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
  psk_key_exchange_modes. The spec matches Firefox 160 captures in cipher
  suites, extension order, the content of every non-random extension and
  the hello length. Covered by `TestFirefox156Spec`,
  `TestFirefox156Handshakes` and `TestSecondaryKeyShareSelectedByServer`.
- `ShuffleChromeTLSExtensions` (`u_parrots.go`) permutes the movable
  extensions uniformly among themselves, as BoringSSL does. Upstream skips
  every swap that touches GREASE, padding or pre_shared_key, so the
  extensions next to them keep their place twice as often (ALPN first in
  11% of Chrome hellos against 5.9%). Covered by
  `TestShuffleChromeTLSExtensionsIsUniform`.

## Updating

Drop a change once upstream ships it, rebase the rest on the new upstream
commit, and run `go test ./...` here and the uTLS tests in Xray-core
(`transport/internet/tls`, `transport/internet/reality`).
