# libtgvoip 2.4.4 — vendoring notes

This directory holds a vendored copy of libtgvoip (the last classic-only
Telegram VoIP library, before tgcalls / WebRTC) compiled into a Windows Phone
8.1 ARM/Win32 static library named **`Vianium.libtgvoip.lib`**.

Today there is no consumer wired up at runtime; the library exists as
groundwork so a future iteration of `VianiumVoIP` (and the managed
consumer in the sibling `vianigram` repo) can fall back to (or replace
its custom `voip_engine.cpp` with) the upstream protocol implementation.

## Source

`third_party/libtgvoip/src/` is a verbatim copy of
`telegram-android/TMessagesProj/jni/voip/libtgvoip/` plus a small
`crypto/` shim that we authored. The upstream tree was pulled in from a
reference checkout — we did not modify it.

## Toolset

- Platform: Windows Phone 8.1 (`<ApplicationType>Windows Phone</ApplicationType>`,
  `<ApplicationTypeRevision>8.1</ApplicationTypeRevision>`)
- Toolset: `v120_wp81` (VS 2013). `v140` does not ship a WP 8.1 platform under
  the installed VS 2015 build tools, so VS 2013 is the only viable option.
- Configuration: **StaticLibrary** for Debug/Release × ARM/Win32.
- C++ standard: 14 (`<LanguageStandard>stdcpp14</LanguageStandard>`).

## Preprocessor switches

```
TGVOIP_USE_CALLBACK_CRYPTO=1   # plug crypto via VoIPController::crypto.* fn ptrs
TGVOIP_NO_DSP=1                # exclude EchoCanceller's WebRTC AudioProcessing path
WINAPI_FAMILY=WINAPI_FAMILY_PHONE_APP
NOMINMAX
_CRT_SECURE_NO_WARNINGS
_ALLOW_KEYWORD_MACROS=1        # silence xkeycheck.h's noexcept-keyword guard
noexcept=throw()               # VS 2013 v120 has no noexcept; emulate for libtgvoip
```

Disabled warnings: `4100 4127 4244 4245 4267 4334 4456 4457 4458 4459 4661
4838 4996`.

## Patches we made to vendored sources

These are deliberate, minimal patches to the upstream code so it parses under
VS 2013. They are clearly commented in-place:

1. **`src/VoIPController.h` → `UnacknowledgedExtraData::operator=`**
   Added an explicit move assignment (the implicit one tries to call the
   deleted `Buffer::operator=`).
2. **`src/VoIPController.h` → `QueuedPacket::operator=`**
   Same — added an explicit move assignment for the same reason.
3. **`src/VoIPController.h` → `UnacknowledgedExtraData(unsigned char, Buffer&&, uint32_t)`**
   Body assigned `data=_data;` where `_data` is named therefore lvalue. Patched
   to `data=std::move(_data);`. Latent bug in upstream that compilers with
   relaxed rvalue-binding rules silently miscompile.
4. **`src/VoIPController.cpp` → `constexpr int64_t` → `const int64_t`**
   Eight call-sites; v120 doesn't accept `constexpr` here.
5. **`src/VoIPController.cpp` → `GetDebugLog()`**
   Returns an empty `"{}"` string under VS 2013 because the json11
   `Json::object{...}` initializer-list path depends on SFINAE constructors
   that v120 cannot parse (see point 7).
6. **`src/OpusDecoder.cpp:229`** — `constexpr float coeffs[]` → `static const float coeffs[]`.
7. **`src/json11.hpp`** — three template `Json` constructors guarded behind
   `!(_MSC_VER && _MSC_VER <= 1800)`. They use `is_constructible<Json, ...>`
   *while `Json` is still incomplete*; v120 chokes. Other compilers and the
   minimal use-cases in libtgvoip don't need them.

If/when we move to a newer toolset, points 4–7 should all be reverted.

## Files excluded from the build (`<ExcludedFromBuild>true</ExcludedFromBuild>`)

These are still on disk so `git diff` against upstream stays clean and a
future Visual Studio with proper WP 8.1 v141 support can re-enable them.

| File | Reason |
| --- | --- |
| `src/audio/AudioIO.cpp` | Brings in `AudioInputWave` / `AudioOutputWave` (MMSYSTEM, banned in WP 8.1) and the WASAPI variants below. |
| `src/audio/AudioIOCallback.cpp` | Depends on `AudioIO`. |
| `src/audio/AudioInput.cpp` | Same. |
| `src/audio/AudioOutput.cpp` | Same. |
| `src/os/windows/AudioInputWave.cpp` | Uses `waveInOpen`/`waveOutOpen` etc. — desktop-only MMSYSTEM API not exposed under `WINAPI_FAMILY_PHONE_APP`. |
| `src/os/windows/AudioOutputWave.cpp` | Same. |
| `src/os/windows/AudioInputWASAPI.cpp` | Uses `AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM` / `AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY` and the 5-argument `IAudioClient::Initialize` overload — none of these exist in the WP 8.1 WASAPI subset. Also references `WindowsSandboxUtils::ActivateAudioDevice(IAudioClient2*)`. |
| `src/os/windows/AudioOutputWASAPI.cpp` | Same. |
| `src/os/windows/WindowsSandboxUtils.cpp` | Provides `IAudioClient2*` activation that the WASAPI files above need; no consumer once those are excluded. |
| `src/os/windows/CXWrapper.cpp` | Fails for two reasons under v120: (a) ADL-without-using on `std::wstring` inside the global namespace, and (b) the json11 SFINAE templates that we disable for VS 2013. Re-enable once on v141. |
| `src/video/ScreamCongestionController.cpp` | Uses `constexpr` namespace-scope variable definitions (C++14) that v120 won't accept. |
| `src/video/VideoRenderer.cpp` | Same. |
| `src/video/VideoSource.cpp` | Same. |

WP 8.1 voice calls don't need video, and we'll plug audio capture/render
through our existing `vianium::voip::WinrtVoipAudioDevice` (WASAPI under
MediaCapture, owned by `VianiumVoIP` in this repo), so the excluded
files are not on the critical path for the Vianigram use case.

## Crypto bridge

`src/crypto/callback_bindings.cpp` declares `RegisterTgvoipCryptoCallbacks()`
and stub function pointers that match libtgvoip's `tgvoip::VoIPController::CryptoFunctions`
shape. Today the bodies are empty — wiring them to the real implementations
in the sibling repo `../../../vianium-crypto/` (AES-IGE encrypt/decrypt,
SHA-1, SHA-256) will happen at the consumer layer (`VianiumVoIP` in this
repo), where the foundation libraries are already linked.

## Output layout

```
ARM\Debug\libtgvoip\Vianium.libtgvoip.lib
ARM\Release\libtgvoip\Vianium.libtgvoip.lib
Win32\Debug\libtgvoip\Vianium.libtgvoip.lib
Win32\Release\libtgvoip\Vianium.libtgvoip.lib
```

A `<Target Name="SyncSolutionLayoutOutputs" AfterTargets="Build">` step also
copies the `.lib` and `.pdb` to `$(SolutionDir)\$(Platform)\$(Configuration)\libtgvoip\`
so the rest of the solution finds it via the same convention as
`VianiumVoIP.vcxproj`.

## Solution wiring

- Added under the `Native` solution folder of the consuming Vianigram
  solution with ProjectGuid `{D6E7F8A9-B0CB-4ECF-D034-E7F8A9BBCC1D}`.
- `VianiumVoIP.vcxproj` carries a `ProjectReference` to it (no link, no
  output assembly — purely for build ordering / future use).

## Known cosmetic warnings

- `LNK4264` from `lib.exe` for every `.obj` archived with `/ZW` — the WP 8.1
  default for app/component projects. Disabling `CompileAsWinRT` breaks
  `NetworkSocketWinsock.cpp` (it references `Platform::String^`) and
  `snprintf` (only declared in C++/CX mode under v120), so we keep `/ZW` on
  and accept the cosmetic warning.
- A handful of `C4068` (unknown pragma — `#pragma clang ...` blocks) and
  `C4018` / `C4101` from upstream code; left as warnings.

## Re-running the build

```powershell
& "C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe" `
  "third_party/libtgvoip/libtgvoip.vcxproj" `
  /p:Configuration=Debug /p:Platform=ARM /nologo /v:m
```
