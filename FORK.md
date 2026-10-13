# Xray-core fork of uTLS

This branch is `github.com/refraction-networking/utls` at `aa6edf4b11af`
("feat: add safari 26.3"), the version Xray-core pins, plus the changes
below. Xray-core uses it through a `replace` in its `go.mod`; the module path
stays `github.com/refraction-networking/utls`.

## Changes

- Keep the private keys of the classical key shares after the first, by
  group (`KeySharePrivateKeys.EcdheFallback`), and derive the shared secret
  with the one the server selected (`establishHandshakeKeys`). Upstream keeps
  the first only, so a Firefox fingerprint (key shares X25519, P-256) fails
  with "tls: invalid server key share" against a server that selects P-256
  (refraction-networking/utls#402). Backport of
  refraction-networking/utls#416. Covered by
  `TestSecondaryKeyShareSelectedByServer`.

## Updating

Drop a change once upstream ships it, rebase the rest on the new upstream
commit, and run `go test ./...` here and the uTLS tests in Xray-core
(`transport/internet/tls`, `transport/internet/reality`).
