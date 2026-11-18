# Firefox 156 and Edge 157 ClientHello fixtures

`firefox156_clienthello.hex` and `edge157_clienthello.hex` are each the
complete first TLS record of a fresh HTTPS connection (no `pre_shared_key`),
as the browser sent it:

| Fixture | Browser | Record | SHA-256 of the handshake message |
| --- | --- | ---: | --- |
| `firefox156_clienthello.hex` | Firefox 156.0.1, official Linux x86_64 build | 1 896 bytes | `1436caa76d4dac4582929007eb930dc5d11f8b8ee7faa2fd513a27af1b7580cd` |
| `edge157_clienthello.hex` | Microsoft Edge 157.0.4341.60, official Linux x86_64 build | 1 768 bytes | `2e221beb1d0bf588adcc1c5375f35d92fc6cc03ca8806ef5a79439e34ad98ba8` |

Both were captured on November 16, 2026, on Debian 13 (Linux 6.12), with
each browser running headless in its own network namespace and a fresh
profile, and loading `https://nginx.example.test/` from a local nginx 1.26
over TCP. `tcpdump -U` recorded the client's side of the namespace's veth.
The record was taken from the first TCP stream of the capture by
reassembling the client's bytes and cutting the first TLS record; the bytes
are unchanged. Neither keys nor server traffic are kept.

`u_browser_captures_test.go` builds `HelloFirefox_156` and `HelloEdge_157`
for the same server name and compares:

- Firefox: cipher suites, extension order, record length, and every
  extension body except the key shares (group and length only) and the
  GREASE ECH config id, AEAD (AES-128-GCM or ChaCha20-Poly1305, which NSS
  picks per hello), enc and payload bytes.
- Edge: cipher suites, the extension multiset with every deterministic body
  (GREASE values, key shares and the GREASE ECH as in
  `chrome155_clienthello.md`), and GREASE first and last. The order between
  is shuffled in both.

GREASE values in these captures are as sent. In the 449 fresh and resumed
Chrome and Edge hellos recorded the same way, the cipher-suite GREASE
equals one of the two extension GREASE values in 53 (11.8%), about what
independent draws give (2 in 16).
