// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "winrt_voip_audio_device.h"

#include "opus_voip_codec.h"

#include <audioclient.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <mmdeviceapi.h>
#include <roapi.h>
#include <sstream>
#include <wrl.h>
#include <wrl/implements.h>

using namespace Microsoft::WRL;
using namespace Platform;
using namespace Windows::Media::Devices;
using namespace Windows::Phone::Media::Devices;

namespace vianigram { namespace voip { namespace infrastructure {

namespace {

template <class T>
void SafeRelease(T** value) {
    if (value != nullptr && *value != nullptr) {
        (*value)->Release();
        *value = nullptr;
    }
}

std::string HResultMessage(const char* prefix, HRESULT hr) {
    std::ostringstream s;
    s << prefix << " hr=0x" << std::hex << (unsigned int)hr;
    return s.str();
}

class AudioActivationHandler :
    public RuntimeClass<RuntimeClassFlags<ClassicCom>, FtmBase, IActivateAudioInterfaceCompletionHandler> {
public:
    explicit AudioActivationHandler(HANDLE eventHandle)
        : EventHandle(eventHandle),
          Client(nullptr),
          ActivateResult(E_FAIL) {}

    STDMETHOD(ActivateCompleted)(IActivateAudioInterfaceAsyncOperation* operation) {
        HRESULT operationResult = E_FAIL;
        IUnknown* unknown = nullptr;
        HRESULT hr = operation->GetActivateResult(&operationResult, &unknown);
        ActivateResult = operationResult;
        if (SUCCEEDED(hr) && SUCCEEDED(operationResult) && unknown != nullptr) {
            unknown->QueryInterface(IID_PPV_ARGS(&Client));
            unknown->Release();
        }
        ::SetEvent(EventHandle);
        return hr;
    }

    HANDLE EventHandle;
    IAudioClient2* Client;
    HRESULT ActivateResult;
};

IAudioClient2* ActivateAudioClient(Platform::String^ deviceId, HRESULT* callResult, HRESULT* activateResult) {
    if (callResult != nullptr) *callResult = E_FAIL;
    if (activateResult != nullptr) *activateResult = E_FAIL;
    if (deviceId == nullptr) return nullptr;

    HANDLE completed = ::CreateEventEx(nullptr, nullptr, 0, EVENT_ALL_ACCESS);
    if (completed == nullptr) {
        if (callResult != nullptr) *callResult = HRESULT_FROM_WIN32(::GetLastError());
        return nullptr;
    }

    ComPtr<AudioActivationHandler> handler = Make<AudioActivationHandler>(completed);
    IActivateAudioInterfaceAsyncOperation* operation = nullptr;
    HRESULT call = ::ActivateAudioInterfaceAsync(
        deviceId->Data(),
        __uuidof(IAudioClient2),
        nullptr,
        handler.Get(),
        &operation);
    if (callResult != nullptr) *callResult = call;
    if (FAILED(call)) {
        ::CloseHandle(completed);
        return nullptr;
    }

    DWORD wait = ::WaitForSingleObjectEx(completed, 10000, false);
    ::CloseHandle(completed);
    if (operation != nullptr) operation->Release();
    if (wait != WAIT_OBJECT_0) {
        if (activateResult != nullptr) *activateResult = HRESULT_FROM_WIN32(WAIT_TIMEOUT);
        return nullptr;
    }

    if (activateResult != nullptr) *activateResult = handler->ActivateResult;
    return handler->Client;
}

WAVEFORMATEX BuildWaveFormat() {
    WAVEFORMATEX format = {};
    format.wFormatTag = WAVE_FORMAT_PCM;
    format.nChannels = WinrtVoipAudioDevice::Channels;
    format.nSamplesPerSec = WinrtVoipAudioDevice::SampleRate;
    format.wBitsPerSample = 16;
    format.nBlockAlign = static_cast<WORD>((format.nChannels * format.wBitsPerSample) / 8);
    format.nAvgBytesPerSec = format.nSamplesPerSec * format.nBlockAlign;
    return format;
}

} // namespace

WinrtVoipAudioDevice::WinrtVoipAudioDevice()
    : m_shutdownEvent(nullptr),
      m_captureEvent(nullptr),
      m_renderEvent(nullptr),
      m_captureThread(nullptr),
      m_renderThread(nullptr),
      m_captureClient(nullptr),
      m_captureService(nullptr),
      m_renderClient(nullptr),
      m_renderService(nullptr),
      m_open(false),
      m_muted(false),
      m_speakerOn(false),
      m_failed(false) {
}

WinrtVoipAudioDevice::~WinrtVoipAudioDevice() {
    Close();
}

ports::outbound::VoipAudioIoResult WinrtVoipAudioDevice::Open() {
    if (m_open) {
        return ports::outbound::VoipAudioIoResult::Ok(SampleRate, Channels, FrameSamples);
    }

    HRESULT co = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(co) && co != RPC_E_CHANGED_MODE) {
        return ports::outbound::VoipAudioIoResult::Fail(HResultMessage("CoInitializeEx failed", co));
    }

    m_shutdownEvent = ::CreateEventEx(nullptr, nullptr, 0, EVENT_MODIFY_STATE | SYNCHRONIZE);
    m_captureEvent = ::CreateEventEx(nullptr, nullptr, 0, EVENT_MODIFY_STATE | SYNCHRONIZE);
    m_renderEvent = ::CreateEventEx(nullptr, nullptr, 0, EVENT_MODIFY_STATE | SYNCHRONIZE);
    if (m_shutdownEvent == nullptr || m_captureEvent == nullptr || m_renderEvent == nullptr) {
        Close();
        return ports::outbound::VoipAudioIoResult::Fail("WASAPI event creation failed");
    }

    ports::outbound::VoipAudioIoResult capture = OpenCapture();
    if (!capture.Success) {
        Close();
        return capture;
    }

    ports::outbound::VoipAudioIoResult render = OpenRender();
    if (!render.Success) {
        Close();
        return render;
    }

    HRESULT hr = m_captureClient->Start();
    if (FAILED(hr)) {
        Close();
        return ports::outbound::VoipAudioIoResult::Fail(HResultMessage("audio capture start failed", hr));
    }

    hr = m_renderClient->Start();
    if (FAILED(hr)) {
        Close();
        return ports::outbound::VoipAudioIoResult::Fail(HResultMessage("audio render start failed", hr));
    }

    m_captureThread = ::CreateThread(nullptr, 0, CaptureThreadProc, this, 0, nullptr);
    m_renderThread = ::CreateThread(nullptr, 0, RenderThreadProc, this, 0, nullptr);
    if (m_captureThread == nullptr || m_renderThread == nullptr) {
        Close();
        return ports::outbound::VoipAudioIoResult::Fail("WASAPI worker thread creation failed");
    }

    m_open = true;
    return ports::outbound::VoipAudioIoResult::Ok(SampleRate, Channels, FrameSamples);
}

void WinrtVoipAudioDevice::Close() {
    if (m_shutdownEvent != nullptr) {
        ::SetEvent(m_shutdownEvent);
    }

    if (m_captureThread != nullptr) {
        ::WaitForSingleObjectEx(m_captureThread, 3000, false);
        ::CloseHandle(m_captureThread);
        m_captureThread = nullptr;
    }
    if (m_renderThread != nullptr) {
        ::WaitForSingleObjectEx(m_renderThread, 3000, false);
        ::CloseHandle(m_renderThread);
        m_renderThread = nullptr;
    }

    if (m_captureClient != nullptr) {
        m_captureClient->Stop();
    }
    if (m_renderClient != nullptr) {
        m_renderClient->Stop();
    }

    SafeRelease(&m_captureService);
    SafeRelease(&m_captureClient);
    SafeRelease(&m_renderService);
    SafeRelease(&m_renderClient);

    if (m_shutdownEvent != nullptr) {
        ::CloseHandle(m_shutdownEvent);
        m_shutdownEvent = nullptr;
    }
    if (m_captureEvent != nullptr) {
        ::CloseHandle(m_captureEvent);
        m_captureEvent = nullptr;
    }
    if (m_renderEvent != nullptr) {
        ::CloseHandle(m_renderEvent);
        m_renderEvent = nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(m_captureGate);
        m_captureFrames.clear();
        m_captureScratch.clear();
    }
    {
        std::lock_guard<std::mutex> lock(m_renderGate);
        m_renderFrames.clear();
        m_renderScratch.clear();
    }
    m_captureCv.notify_all();
    m_open = false;
}

ports::outbound::VoipAudioIoResult WinrtVoipAudioDevice::ReadFrame(std::vector<int16_t>* pcm, int timeoutMs) {
    if (pcm == nullptr) {
        return ports::outbound::VoipAudioIoResult::Fail("audio read destination is null");
    }
    if (!m_open) {
        return ports::outbound::VoipAudioIoResult::Fail("audio device is not open");
    }
    if (timeoutMs <= 0) timeoutMs = FrameDurationMs;

    std::unique_lock<std::mutex> lock(m_captureGate);
    if (m_captureFrames.empty()) {
        m_captureCv.wait_for(lock, std::chrono::milliseconds(timeoutMs));
    }
    if (m_captureFrames.empty()) {
        return ports::outbound::VoipAudioIoResult::Fail("audio capture timed out");
    }

    *pcm = m_captureFrames.front();
    m_captureFrames.pop_front();
    if (m_muted) {
        std::fill(pcm->begin(), pcm->end(), 0);
    }
    return ports::outbound::VoipAudioIoResult::Ok(SampleRate, Channels, FrameSamples);
}

ports::outbound::VoipAudioIoResult WinrtVoipAudioDevice::WriteFrame(const int16_t* pcm, size_t samples) {
    if (!m_open) {
        return ports::outbound::VoipAudioIoResult::Fail("audio device is not open");
    }
    if (pcm == nullptr || samples == 0) {
        return ports::outbound::VoipAudioIoResult::Fail("audio render frame is empty");
    }

    std::vector<int16_t> copy(pcm, pcm + samples);
    {
        std::lock_guard<std::mutex> lock(m_renderGate);
        while (m_renderFrames.size() >= 12) {
            m_renderFrames.pop_front();
        }
        m_renderFrames.push_back(copy);
    }
    return ports::outbound::VoipAudioIoResult::Ok(SampleRate, Channels, FrameSamples);
}

void WinrtVoipAudioDevice::SetMuted(bool muted) {
    m_muted = muted;
}

void WinrtVoipAudioDevice::SetSpeaker(bool speakerOn) {
    m_speakerOn = speakerOn;

    // Switch the call audio route as well as flipping m_speakerOn:
    // without this the audio output stays on whatever route the OS picked
    // at OpenRender (Communications role = earpiece by default on phones),
    // so tapping Speaker would have no audible effect.
    //
    // Windows.Phone.Media.Devices.AudioRoutingManager is the WP8.1 API for
    // mid-call route switching. It's only valid during an active VoIP
    // session (AudioCategory_Communications); calls outside of that
    // context throw COMException E_ACCESSDENIED. Wrapping in try/catch
    // keeps the audio device alive if the OS rejects the request.
    try {
        AudioRoutingManager^ manager = AudioRoutingManager::GetDefault();
        if (manager != nullptr) {
            AudioRoutingEndpoint endpoint = speakerOn
                ? AudioRoutingEndpoint::Speakerphone
                : AudioRoutingEndpoint::Earpiece;
            manager->SetAudioEndpoint(endpoint);
            std::ostringstream s;
            s << "[WinrtVoipAudioDevice] SetSpeaker route="
              << (speakerOn ? "Speakerphone" : "Earpiece") << "\n";
            ::OutputDebugStringA(s.str().c_str());
        }
    } catch (Platform::Exception^ ex) {
        std::ostringstream s;
        s << "[WinrtVoipAudioDevice] SetSpeaker route change failed hr=0x"
          << std::hex << (unsigned int)ex->HResult << "\n";
        ::OutputDebugStringA(s.str().c_str());
    } catch (...) {
        ::OutputDebugStringA("[WinrtVoipAudioDevice] SetSpeaker route change threw\n");
    }
}

DWORD WINAPI WinrtVoipAudioDevice::CaptureThreadProc(void* arg) {
    static_cast<WinrtVoipAudioDevice*>(arg)->CaptureLoop();
    return 0;
}

DWORD WINAPI WinrtVoipAudioDevice::RenderThreadProc(void* arg) {
    static_cast<WinrtVoipAudioDevice*>(arg)->RenderLoop();
    return 0;
}

ports::outbound::VoipAudioIoResult WinrtVoipAudioDevice::OpenCapture() {
    Platform::String^ deviceId =
        MediaDevice::GetDefaultAudioCaptureId(AudioDeviceRole::Communications);
    if (deviceId == nullptr) {
        return ports::outbound::VoipAudioIoResult::Fail("default communication microphone was not found");
    }

    HRESULT call = E_FAIL;
    HRESULT activate = E_FAIL;
    IAudioClient2* client = ActivateAudioClient(deviceId, &call, &activate);
    if (client == nullptr || FAILED(call) || FAILED(activate)) {
        SafeRelease(&client);
        return ports::outbound::VoipAudioIoResult::Fail(
            FAILED(call)
                ? HResultMessage("microphone activation failed", call)
                : HResultMessage("microphone activation result failed", activate));
    }

    AudioClientProperties properties = {};
    properties.cbSize = sizeof(AudioClientProperties);
    properties.eCategory = AudioCategory_Communications;
    HRESULT hr = client->SetClientProperties(&properties);
    if (FAILED(hr)) {
        SafeRelease(&client);
        return ports::outbound::VoipAudioIoResult::Fail(HResultMessage("microphone communication category failed", hr));
    }

    WAVEFORMATEX format = BuildWaveFormat();
    const GUID sessionGuid = { 0x2c693079, 0x3f59, 0x49fd, { 0x96, 0x4f, 0x61, 0xc0, 0x05, 0xea, 0xa5, 0xd3 } };
    hr = client->Initialize(
        AUDCLNT_SHAREMODE_SHARED,
        AUDCLNT_STREAMFLAGS_EVENTCALLBACK |
            AUDCLNT_STREAMFLAGS_NOPERSIST,
        1000 * 10000,
        0,
        &format,
        &sessionGuid);
    if (FAILED(hr)) {
        SafeRelease(&client);
        return ports::outbound::VoipAudioIoResult::Fail(HResultMessage("microphone initialize failed", hr));
    }

    hr = client->SetEventHandle(m_captureEvent);
    if (FAILED(hr)) {
        SafeRelease(&client);
        return ports::outbound::VoipAudioIoResult::Fail(HResultMessage("microphone event handle failed", hr));
    }

    hr = client->GetService(IID_PPV_ARGS(&m_captureService));
    if (FAILED(hr)) {
        SafeRelease(&client);
        return ports::outbound::VoipAudioIoResult::Fail(HResultMessage("microphone capture service failed", hr));
    }

    m_captureClient = client;
    return ports::outbound::VoipAudioIoResult::Ok(SampleRate, Channels, FrameSamples);
}

ports::outbound::VoipAudioIoResult WinrtVoipAudioDevice::OpenRender() {
    Platform::String^ deviceId =
        MediaDevice::GetDefaultAudioRenderId(AudioDeviceRole::Communications);
    if (deviceId == nullptr) {
        return ports::outbound::VoipAudioIoResult::Fail("default communication speaker was not found");
    }

    HRESULT call = E_FAIL;
    HRESULT activate = E_FAIL;
    IAudioClient2* client = ActivateAudioClient(deviceId, &call, &activate);
    if (client == nullptr || FAILED(call) || FAILED(activate)) {
        SafeRelease(&client);
        return ports::outbound::VoipAudioIoResult::Fail(
            FAILED(call)
                ? HResultMessage("speaker activation failed", call)
                : HResultMessage("speaker activation result failed", activate));
    }

    AudioClientProperties properties = {};
    properties.cbSize = sizeof(AudioClientProperties);
    properties.eCategory = AudioCategory_Communications;
    HRESULT hr = client->SetClientProperties(&properties);
    if (FAILED(hr)) {
        SafeRelease(&client);
        return ports::outbound::VoipAudioIoResult::Fail(HResultMessage("speaker communication category failed", hr));
    }

    WAVEFORMATEX format = BuildWaveFormat();
    const GUID sessionGuid = { 0x2c693079, 0x3f59, 0x49fd, { 0x96, 0x4f, 0x61, 0xc0, 0x05, 0xea, 0xa5, 0xd3 } };
    hr = client->Initialize(
        AUDCLNT_SHAREMODE_SHARED,
        AUDCLNT_STREAMFLAGS_EVENTCALLBACK |
            AUDCLNT_STREAMFLAGS_NOPERSIST,
        60 * 10000,
        0,
        &format,
        &sessionGuid);
    if (FAILED(hr)) {
        SafeRelease(&client);
        return ports::outbound::VoipAudioIoResult::Fail(HResultMessage("speaker initialize failed", hr));
    }

    hr = client->SetEventHandle(m_renderEvent);
    if (FAILED(hr)) {
        SafeRelease(&client);
        return ports::outbound::VoipAudioIoResult::Fail(HResultMessage("speaker event handle failed", hr));
    }

    hr = client->GetService(IID_PPV_ARGS(&m_renderService));
    if (FAILED(hr)) {
        SafeRelease(&client);
        return ports::outbound::VoipAudioIoResult::Fail(HResultMessage("speaker render service failed", hr));
    }

    UINT32 bufferFrames = 0;
    hr = client->GetBufferSize(&bufferFrames);
    if (FAILED(hr)) {
        SafeRelease(&m_renderService);
        SafeRelease(&client);
        return ports::outbound::VoipAudioIoResult::Fail(HResultMessage("speaker buffer size failed", hr));
    }

    BYTE* data = nullptr;
    hr = m_renderService->GetBuffer(bufferFrames, &data);
    if (SUCCEEDED(hr)) {
        m_renderService->ReleaseBuffer(bufferFrames, AUDCLNT_BUFFERFLAGS_SILENT);
    }

    m_renderClient = client;
    return ports::outbound::VoipAudioIoResult::Ok(SampleRate, Channels, FrameSamples);
}

void WinrtVoipAudioDevice::CaptureLoop() {
    ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    HANDLE waitHandles[] = { m_shutdownEvent, m_captureEvent };

    while (true) {
        DWORD wait = ::WaitForMultipleObjectsEx(2, waitHandles, false, INFINITE, false);
        if (wait == WAIT_OBJECT_0) {
            return;
        }
        if (wait != WAIT_OBJECT_0 + 1 || m_captureService == nullptr) {
            continue;
        }

        UINT32 packetFrames = 0;
        HRESULT hr = m_captureService->GetNextPacketSize(&packetFrames);
        if (FAILED(hr)) {
            m_failed = true;
            return;
        }

        while (packetFrames > 0) {
            BYTE* data = nullptr;
            UINT32 framesAvailable = 0;
            DWORD flags = 0;
            hr = m_captureService->GetBuffer(&data, &framesAvailable, &flags, nullptr, nullptr);
            if (FAILED(hr)) {
                m_failed = true;
                return;
            }

            if (framesAvailable > 0) {
                if (flags & AUDCLNT_BUFFERFLAGS_SILENT) {
                    std::vector<int16_t> silence(framesAvailable, 0);
                    PushCaptureSamples(silence.empty() ? nullptr : &silence[0], silence.size());
                } else {
                    PushCaptureSamples(reinterpret_cast<const int16_t*>(data), framesAvailable);
                }
            }

            m_captureService->ReleaseBuffer(framesAvailable);
            hr = m_captureService->GetNextPacketSize(&packetFrames);
            if (FAILED(hr)) {
                m_failed = true;
                return;
            }
        }
    }
}

void WinrtVoipAudioDevice::RenderLoop() {
    ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    HANDLE waitHandles[] = { m_shutdownEvent, m_renderEvent };

    while (true) {
        DWORD wait = ::WaitForMultipleObjectsEx(2, waitHandles, false, INFINITE, false);
        if (wait == WAIT_OBJECT_0) {
            return;
        }
        if (wait != WAIT_OBJECT_0 + 1 || m_renderClient == nullptr || m_renderService == nullptr) {
            continue;
        }

        UINT32 bufferFrames = 0;
        UINT32 padding = 0;
        HRESULT hr = m_renderClient->GetBufferSize(&bufferFrames);
        if (FAILED(hr)) {
            m_failed = true;
            return;
        }
        hr = m_renderClient->GetCurrentPadding(&padding);
        if (FAILED(hr)) {
            m_failed = true;
            return;
        }

        UINT32 framesAvailable = bufferFrames > padding ? bufferFrames - padding : 0;
        if (framesAvailable == 0) continue;

        BYTE* data = nullptr;
        hr = m_renderService->GetBuffer(framesAvailable, &data);
        if (FAILED(hr)) {
            m_failed = true;
            return;
        }
        FillRenderSamples(reinterpret_cast<int16_t*>(data), framesAvailable);
        hr = m_renderService->ReleaseBuffer(framesAvailable, 0);
        if (FAILED(hr)) {
            m_failed = true;
            return;
        }
    }
}

void WinrtVoipAudioDevice::PushCaptureSamples(const int16_t* samples, size_t sampleCount) {
    if (sampleCount == 0) return;
    std::lock_guard<std::mutex> lock(m_captureGate);
    size_t old = m_captureScratch.size();
    m_captureScratch.resize(old + sampleCount);
    if (samples == nullptr) {
        std::fill(m_captureScratch.begin() + old, m_captureScratch.end(), 0);
    } else {
        std::copy(samples, samples + sampleCount, m_captureScratch.begin() + old);
    }

    while (m_captureScratch.size() >= FrameSamples) {
        std::vector<int16_t> frame(m_captureScratch.begin(), m_captureScratch.begin() + FrameSamples);
        m_captureScratch.erase(m_captureScratch.begin(), m_captureScratch.begin() + FrameSamples);
        while (m_captureFrames.size() >= 8) {
            m_captureFrames.pop_front();
        }
        m_captureFrames.push_back(frame);
    }
    m_captureCv.notify_one();
}

void WinrtVoipAudioDevice::FillRenderSamples(int16_t* samples, size_t sampleCount) {
    if (samples == nullptr || sampleCount == 0) return;
    size_t written = 0;
    std::lock_guard<std::mutex> lock(m_renderGate);

    while (written < sampleCount) {
        if (m_renderScratch.empty()) {
            if (m_renderFrames.empty()) {
                std::fill(samples + written, samples + sampleCount, 0);
                return;
            }
            m_renderScratch = m_renderFrames.front();
            m_renderFrames.pop_front();
        }

        size_t toCopy = m_renderScratch.size();
        if (toCopy > sampleCount - written) toCopy = sampleCount - written;
        std::memcpy(samples + written, &m_renderScratch[0], toCopy * sizeof(int16_t));
        written += toCopy;
        m_renderScratch.erase(m_renderScratch.begin(), m_renderScratch.begin() + toCopy);
    }
}

bool WinrtVoipAudioRuntimeFactory::IsAvailable(std::string* reason) const {
    if (reason != nullptr) reason->clear();
    return true;
}

std::unique_ptr<ports::outbound::IVoipAudioDevice> WinrtVoipAudioRuntimeFactory::CreateDevice() {
    return std::unique_ptr<ports::outbound::IVoipAudioDevice>(new WinrtVoipAudioDevice());
}

std::unique_ptr<ports::outbound::IVoipAudioCodec> WinrtVoipAudioRuntimeFactory::CreateCodec() {
    return std::unique_ptr<ports::outbound::IVoipAudioCodec>(new OpusVoipCodec());
}

}}} // namespace vianigram::voip::infrastructure
