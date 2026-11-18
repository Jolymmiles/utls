# Firefox 156, Edge 157 and Safari 27 ClientHello fixtures

`firefox156_clienthello.hex`, `edge157_clienthello.hex` and
`safari27_clienthello.hex` are each the complete first TLS record of a
fresh HTTPS connection (no `pre_shared_key`), as the browser sent it:

| Fixture | Browser | Record | SHA-256 of the handshake message |
| --- | --- | ---: | --- |
| `firefox156_clienthello.hex` | Firefox 156.0.1, official Linux x86_64 build | 1 896 bytes | `1436caa76d4dac4582929007eb930dc5d11f8b8ee7faa2fd513a27af1b7580cd` |
| `edge157_clienthello.hex` | Microsoft Edge 157.0.4341.60, official Linux x86_64 build | 1 768 bytes | `2e221beb1d0bf588adcc1c5375f35d92fc6cc03ca8806ef5a79439e34ad98ba8` |
| `safari27_clienthello.hex` | Safari 27.3 (22626.1.17) on macOS 27.3 (26C5047e), arm64 | 1 535 bytes | `0fedf608b4e8d94ceace3ff87c7bd8c7329ccd7427dbefac5192c7151f4d14be` |

The Firefox and Edge records were captured on November 16, 2026, on
Debian 13 (Linux 6.12), with each browser running headless in its own
network namespace and a fresh profile, and loading
`https://nginx.example.test/` from a local nginx 1.26 over TCP.
`tcpdump -U` recorded the client's side of the namespace's veth.
The record was taken from the first TCP stream of the capture by
reassembling the client's bytes and cutting the first TLS record; the bytes
are unchanged. Neither keys nor server traffic are kept.

The Safari record was captured on November 18, 2026. Safari, with its
existing profile, loaded `https://c1.localhost:47411/`, a name and port it
had not visited, so it held no session to resume. A listener on 127.0.0.1
read the first TLS record of the first connection and closed it without
answering; the bytes are unchanged. Safari opened eight connections for the
page, and all eight records were 1 535 bytes long. A capture for
`c3.localtest.me`, which public DNS resolves to 127.0.0.1, had the same
cipher suites, extension order and extension bodies once the server
name, GREASE values and key share bytes are set aside, in a record three
bytes longer for the longer name. Both servers were on loopback.

`u_browser_captures_test.go` builds `HelloFirefox_156`, `HelloEdge_157` and
`HelloSafari_26_3` for the same server name and compares:

- Firefox: the record header and length, cipher suites, extension order,
  and every extension body except the key shares (group and length only)
  and the GREASE ECH config id, AEAD (AES-128-GCM or ChaCha20-Poly1305,
  which NSS picks per hello), enc and payload bytes.
- Edge: cipher suites, the extension multiset with every deterministic body
  (GREASE values, key shares and the GREASE ECH as in
  `chrome155_clienthello.md`), the GREASE extensions first and last with
  their bodies, and the GREASE group that supported_groups and key_share
  have in common. The order between is shuffled in both.
- Safari: the record header and length, cipher suites, the extensions in
  wire order with every body, and the GREASE group that supported_groups
  and key_share have in common. GREASE values are free, and key shares are
  compared by group and length.

GREASE values in these captures are as sent. In the 449 fresh and resumed
Chrome and Edge hellos recorded the same way, the cipher-suite GREASE
equals one of the two extension GREASE values in 53 (11.8%), about what
independent draws give (2 in 16).
