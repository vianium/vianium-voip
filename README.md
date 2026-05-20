# vianium-voip
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE) [![Vianium](https://img.shields.io/badge/org-vianium-00A0F0.svg)](https://github.com/vianium) [![Issues](https://img.shields.io/github/issues/vianium/vianium-voip.svg)](https://github.com/vianium/vianium-voip/issues)

> RTP, SRTP, OPUS - VoIP transport for Vianium.

Created and maintained by [Angel Careaga](https://github.com/AngelCareaga).

VoIP transport for Telegram 1:1 calls. Implements the native media plane
(low-latency UDP/RTP, SRTP packet crypto, OPUS encode/decode, jitter
buffering, ICE/STUN/TURN, DTLS-SRTP for `tgcalls`) and builds on top of
the vendored libtgvoip protocol library for the classic Telegram VoIP
wire format. Designed as a C++/CX WinRT component for the Vianigram
Telegram client; the managed call lifecycle and MTProto signaling sit
on the consumer side.

Part of the [Vianium](https://github.com/vianium) ecosystem.

## Status

**Version:** v0.1.0 - initial release  
**Tier:** 2 (Domain protocol library)  
**License:** Apache License 2.0 (original Vianium code) and Unlicense (vendored libtgvoip; preserved verbatim)

## Projects in this repo

This repository consolidates three Visual Studio projects:

| Project | Path | Output | Notes |
|---|---|---|---|
| `VianiumVoIP.vcxproj` | repo root | `Vianium.VoIP.dll` (WinRT component) | Domain, application, infrastructure, and v1 WinMD API. Owns RTP/SRTP, OPUS, jitter buffer, ICE/STUN/TURN, DTLS, reflector transport, and the audio device adapter. |
| `Vianium.Tgcalls.vcxproj` | repo root | `Vianium.Tgcalls.dll` | Pure C++ backend that bridges the tgcalls signaling layer (defined in `VianiumVoIP\src\domain\tgcalls_signaling_*`) onto the native media graph. |
| `third_party/libtgvoip/libtgvoip.vcxproj` | `third_party/libtgvoip/` | `Vianium.libtgvoip.lib` (static) | Vendored libtgvoip 2.4.4 (Grishka). See [`third_party/libtgvoip/VENDORING_NOTES.md`](third_party/libtgvoip/VENDORING_NOTES.md) for the minimal patches applied to make it parse under VS 2013 `v120_wp81`. |

## What this is

The media-plane half of a Telegram voice call. Telegram MTProto signaling
(call request, key exchange, reflector list, ICE candidate exchange) is
handled by the managed `Vianigram` client and projected into this native
module through the v1 WinMD surface. Once a call is connected, this
module owns:

- Telegram VoIP MTProto2-short relay packet crypto: `peer_tag`,
  `msg_key`, KDF2, AES-IGE encrypt/decrypt, and tamper rejection.
- SRTP packet codec (AES-CTR), session key derivation, and the SRTP
  authentication path used by `tgcalls`.
- OPUS encode/decode, a basic jitter buffer with PLC slots, target-latency
  tracking, and the Opus pipeline backing the audio adapter.
- ICE / STUN / TURN message codecs and the agent that pairs candidates,
  including a `DatagramSocket` self-info probe behind an outbound port.
- A minimal DTLS 1.2 client (record + handshake) for `tgcalls` calls that
  use DTLS-SRTP, including the TLS 1.2 PRF wrapper.

## Why it exists

The managed `Vianigram.Calls` context owns the call lifecycle, but the
media plane needs to live in C++ for low-latency UDP/RTP, deterministic
Opus encode/decode, audio capture / playback through WASAPI under
`MediaCapture`, and echo cancellation. Splitting the VoIP transport out
into its own repository lets the protocol code be reviewed, audited, and
consumed independently of the Telegram client.

## Building

This is a Visual Studio `v120_wp81` (VS 2013, Windows Phone 8.1) project
set. From the Vianigram solution it builds as part of the `Native`
project folder; standalone:

```powershell
& "C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe" `
  "VianiumVoIP.vcxproj" `
  /p:Configuration=Release /p:Platform=ARM /nologo /v:m
```

`VianiumVoIP.vcxproj` references `Vianium.Tgcalls.vcxproj` and
`third_party/libtgvoip/libtgvoip.vcxproj`, plus the foundation libraries
in the table below. The Opus sources are not vendored; set `OpusRoot`
on the MSBuild command line (or in a parent `.props`) to point at a
checkout of `telegram-android/TMessagesProj/jni/opus/`. When `OpusRoot`
is unset, the `ThirdPartyOpus` ItemGroup expands to no files and the
project still builds, but runtime Opus encode/decode is unavailable.

## Dependencies

| Repo | Why |
|---|---|
| [vianium-kernel](https://github.com/vianium/vianium-kernel) | `Result<T>`, arena, base types consumed across the domain and application layers. |
| [vianium-crypto](https://github.com/vianium/vianium-crypto) | AES-CTR (SRTP), AES-IGE (relay packet crypto), AES-GCM (DTLS), BigNum, ECDH-P256, HMAC, SHA-1/256/512. Linked via project reference. |
| [vianium-tls](https://github.com/vianium/vianium-tls) | TLS 1.2 PRF wrapper used by the DTLS handshake. Linked via project reference. |
| [vianium-net](https://github.com/vianium/vianium-net) | Transport types, DNS resolution for reflector hostnames. |

## Vianium ecosystem

| Repo | Tier | Purpose |
|---|---|---|
| [vianium-kernel](https://github.com/vianium/vianium-kernel) | 1 - Foundation | Result<T>, arena, event bus, base types |
| [vianium-crypto](https://github.com/vianium/vianium-crypto) | 1 - Foundation | SHA, HMAC, AES, BigNum, ECDH |
| [vianium-tls](https://github.com/vianium/vianium-tls) | 1 - Foundation | TLS 1.3 Mozilla Modern |
| [vianium-net](https://github.com/vianium/vianium-net) | 1 - Foundation | Sockets, DNS, DoH |
| [vianium-http](https://github.com/vianium/vianium-http) | 1 - Foundation | HTTP/1.1, H2, connection pool |
| [vianium-mtproto](https://github.com/vianium/vianium-mtproto) | 2 - Protocol | Telegram MTProto 2.0 + TL |
| [vianium-voip](https://github.com/vianium/vianium-voip) | 2 - Protocol | RTP/SRTP, OPUS, libtgvoip |
| [vianium-browser](https://github.com/vianium/vianium-browser) | 3 - Product | Web browser |
| [vianigram](https://github.com/vianium/vianigram) | 3 - Product | Telegram client |

## Used by

- [vianigram](https://github.com/vianium/vianigram) - Telegram client (Windows Phone 8.1).

## License

The original Vianium code in this repository is licensed under the
**Apache License 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for
full terms.

This library is free to use, modify, redistribute, and include in
commercial or proprietary software, provided the license and attribution
notices are preserved.

### Third-party code

The vendored libtgvoip sources under `third_party/libtgvoip/` are
released by their upstream author under the **Unlicense (public
domain)** and are preserved verbatim. The Apache-2.0 license that covers
the original Vianium code does not apply to those sources. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the full attribution
and [`LICENSES/libtgvoip-Unlicense.txt`](LICENSES/libtgvoip-Unlicense.txt)
for the preserved upstream license text.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require Developer
Certificate of Origin (DCO) sign-off.

## Security

See [SECURITY.md](SECURITY.md) to report vulnerabilities.

## Support this project

Vianium is maintained by [Angel Careaga](https://angelcareaga.com) as a
personal open-source effort. If `vianium-voip` is useful to you, please
consider supporting future work:

- 💖 **[GitHub Sponsors](https://github.com/sponsors/vianium)** — recurring or one-time
- ☕ **[Buy Me a Coffee](https://www.buymeacoffee.com/soyangelcareaga)** — one-time tip, no account needed
- 🌐 **[angelcareaga.com](https://angelcareaga.com)** — contact, consulting

Detailed channels and a transparency page live in
[`SUPPORT.md`](SUPPORT.md) and
[vianium-docs/donations.md](https://github.com/vianium/vianium-docs/blob/main/donations.md).

## Author

**Angel Careaga**  
[hello@angelcareaga.com](mailto:hello@angelcareaga.com)  
[github.com/AngelCareaga](https://github.com/AngelCareaga)  
[angelcareaga.com](https://angelcareaga.com)
