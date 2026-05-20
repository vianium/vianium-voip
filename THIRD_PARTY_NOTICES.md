# Third-Party Notices

This repository includes third-party components. Each component keeps its
original license.

| Component | Version / Commit | License | Source |
|---|---|---|---|
| libtgvoip | 2.4.4 (vendored verbatim) | Unlicense (public domain) | https://github.com/grishka/libtgvoip |
| libopus | telegram-android jni snapshot (CELT + SILK fixed-point) | BSD-3-Clause | https://gitlab.xiph.org/xiph/opus |

## libtgvoip

- **Name:** libtgvoip
- **Author:** Grigory Klyushnikov ("Grishka")
- **Source:** https://github.com/grishka/libtgvoip
- **License:** Unlicense (public domain)
- **Vendored under:** `third_party/libtgvoip/`
- **License text at:** `LICENSES/libtgvoip-Unlicense.txt`
- **Used by:** `Vianium.Tgcalls.vcxproj`

The upstream sources declare themselves as "free and unencumbered public
domain software" in every file header, with the canonical reference at
<http://unlicense.org>. The Apache-2.0 license that covers the original
Vianium code in this repository does not apply to anything under
`third_party/`; those sources remain under their own terms.

A handful of minor, in-place patches were applied to make libtgvoip 2.4.4
parse under the VS 2013 `v120_wp81` toolset (constexpr → const,
SFINAE-template guards in `json11.hpp`, and similar). The patches are
clearly commented inside the affected files and documented in
`third_party/libtgvoip/VENDORING_NOTES.md`. They do not change the
public-domain status of the upstream code.

A small `crypto/callback_bindings.cpp` shim was authored by the Vianium
project and lives under `third_party/libtgvoip/src/crypto/`. It is kept
inside the vendored tree to minimise diff against upstream and is covered
by the same public-domain dedication.

## libopus

- **Name:** libopus
- **Authors:** Xiph.Org, Skype Limited, Octasic, Jean-Marc Valin, Timothy B.
  Terriberry, CSIRO, Gregory Maxwell, Mark Borgerding, Erik de Castro Lopo
  (full list in `third_party/libopus/AUTHORS`).
- **Source:** https://gitlab.xiph.org/xiph/opus
- **License:** BSD-3-Clause
- **Vendored under:** `third_party/libopus/`
- **License text at:** `LICENSES/libopus-BSD-3-Clause.txt`
  (mirrored verbatim from `third_party/libopus/COPYING`)
- **Used by:** `VianiumVoIP.vcxproj` (and the sibling `Vianigram.Core.Voip`
  project in the vianigram repo, which shares this vendor tree via its
  `OpusRoot` property).

The vendored snapshot was taken from the telegram-android opus subtree
(`TMessagesProj/jni/opus/`) to ensure binary compatibility with libtgvoip's
expectations. It includes:

  * `include/`  — public Opus API (`opus.h`, `opus_defines.h`, etc.)
  * `src/`      — the Opus codec front-end (`opus_decoder.c`, `opus_encoder.c`)
  * `silk/`     — SILK voice-band codec (with `silk/fixed/` selected on
                  ARM Phone builds, which lack hardware float)
  * `celt/`     — CELT music-band codec
  * `ogg/`, `opusfile/` — unused at link time; kept to preserve the original
                          tree layout but not pulled into the build.

Build configuration headers (`config.h`, `c_utils.h`) live in
`src/voip/src/third_party/opus_config/` and select `FIXED_POINT`,
`OPUS_BUILD`, and similar defines required by `silk/fixed`. The vcxproj
glob-includes only the `src/`, `silk/`, `silk/fixed/`, and `celt/` C
sources so we never accidentally compile the Ogg/opusfile wrappers.

## Adding new third-party code

When adding new third-party code:

- Preserve the upstream license verbatim under `LICENSES/`.
- Add the component to the table above.
- Keep copyright notices intact in every source file.
- Confirm the license is compatible with Apache-2.0 (the license of the
  original Vianium code in this repository).
