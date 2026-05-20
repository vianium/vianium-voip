# Changelog — vianium-voip

All notable changes to this repository are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/).

Unreleased changes are listed under `## [Unreleased]`. Each tagged
release moves the content from there into a dated `## [vX.Y.Z] — YYYY-MM-DD`
heading.

---

## [Unreleased]

### Added
- libopus vendored in-tree under `third_party/libopus/` (BSD-3-Clause,
  Xiph.Org). Snapshot is the `TMessagesProj/jni/opus/` subtree from
  telegram-android, kept whole to retain SIMD subdirectories. Required
  for libtgvoip's encoder/decoder and our `opus_voip_codec`. License
  mirrored to `LICENSES/libopus-BSD-3-Clause.txt` and listed in
  `THIRD_PARTY_NOTICES.md`. The `OpusRoot` MSBuild property now
  defaults to the vendored tree.
- Sibling consumers (`Vianigram.Core.Voip` had been a stale duplicate
  of this repo; it was removed from the vianigram repo. Vianigram now
  consumes `Vianium.VoIP.dll` directly).

### Changed
- _Track changes to existing behaviour._

### Deprecated
- _Track soon-to-be-removed surfaces._

### Removed
- _Track removed features (only after a deprecation period)._

### Fixed
- _Track bug fixes._

### Security
- _Track security-relevant fixes (CVE references where applicable)._

---

## [v0.1.0] — TBD

Initial public release as part of the [Vianium](https://github.com/vianium)
org migration. License: Apache-2.0. Tier: Domain.

See [`NOTICE`](NOTICE) for copyright attribution and
[`vianium-docs/MIGRATION_PLAN.md`](https://github.com/vianium/vianium-docs/blob/main/MIGRATION_PLAN.md)
for the cross-repo migration narrative.

[Unreleased]: https://github.com/vianium/vianium-voip/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/vianium/vianium-voip/releases/tag/v0.1.0
