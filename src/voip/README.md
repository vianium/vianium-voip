# VianiumVoIP

Native VoIP bounded context for Telegram 1:1 calls.

This module is intentionally native (C++/CX WinRT component) because the
media plane needs low-latency UDP/RTP, Opus encode/decode, jitter buffering,
audio capture/playback, and echo cancellation. The managed `Vianigram.Calls`
context owns only MTProto signaling and call lifecycle orchestration.

Current status:

- The architectural shell is present and builds as `Vianium.VoIP.dll`.
- The v1 WinMD exposes capability and operation results.
- Telegram call DH is implemented natively: outgoing `g_a_hash`, incoming
  `g_b`, shared-key fingerprint verification, and opaque key handles.
- The managed Calls context projects Telegram reflector endpoints into the
  native module, where endpoint selection prefers usable IPv4 reflectors with
  `peer_tag`.
- UDP reflector packet shapes and a WinRT `DatagramSocket` self-info probe are
  implemented behind an outbound port.
- Telegram VoIP MTProto2-short relay packet crypto is implemented natively:
  `peer_tag`, `msg_key`, KDF2, AES-IGE encrypt/decrypt, and tamper rejection.
- A basic jitter buffer tracks playout, PLC slots, late drops, and target
  latency for the upcoming Opus pipeline.
- Capability is still reported as key-exchange-only until the audio plane is
  complete: Opus encode/decode, audio capture/playback, packet pump, and echo
  cancellation.

Related modules:

- VianiumBrowser crypto primitives currently provide BigNum/SHA/randomness for
  call DH; key bytes stay inside this native module.
- `Vianigram.Core.Media` currently has Opus decoder/encoder headers and stubs.
  Call-side Opus must be native for WP8.1 latency/CPU control; `_vendor`
  contains Concentus/libopus and Telegram protocol references, but this module
  must expose only Vianigram-owned ports and implementations.
- `Vianigram.Calls` consumes this module through a composition adapter, never
  by referencing implementation types from its domain/application layers.
