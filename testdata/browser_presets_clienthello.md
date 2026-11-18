# Full ClientHello captures

Chrome 157.0.8103.78, Edge 157.0.4341.60, and Firefox 160.0 ran in
Linux containers against the same local nginx target. The comparison
used full TLS ClientHellos for `nginx.example.test`.
The [capture fields](browser_presets_clienthello.json) contain each
observed cipher suite ID, extension ID, and extension length in wire order.

| Browser | Captured full hellos | Generated uTLS hellos | Comparison |
| --- | ---: | ---: | --- |
| Chrome 157 | 2 | 5 | Cipher suite order, extension multiset, and non-ECH extension lengths matched |
| Edge 157 | 1 | 5 | Cipher suite order, extension multiset, and non-ECH extension lengths matched |
| Firefox 160 | 1 | 5 | Cipher suite order, extension order, and extension lengths matched |

The comparison treats GREASE values as equivalent. Chromium shuffles the
movable extensions, so the Chrome and Edge checks preserve multiplicity
and compare the extensions without order. Every observed Chromium ECH
payload length belonged to the preset's four supported lengths
(`186`, `218`, `250`, `282`). Edge's capture lacked the `trust_anchors`
extension present in Chrome. The Edge preset also had no `trust_anchors`.
Firefox's ECH extension measured 282 bytes in both the capture and the preset.

The sample covers full ClientHellos only. The shuffle distribution has
its own statistical test. Resumption and iOS require separate captures.
