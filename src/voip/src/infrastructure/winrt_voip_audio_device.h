// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include "../ports/outbound/i_voip_audio_runtime.h"

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>
#include <windows.h>

struct IAudioClient;
struct IAudioCaptureClient;
struct IAudioRenderClient;

namespace vianigram { namespace voip { namespace infrastructure {

class WinrtVoipAudioDevice : public ports::outbound::IVoipAudioDevice {
public:
    enum {
        SampleRate = 48000,
        Channels = 1,
        FrameDurationMs = 60,
        FrameSamples = (SampleRate / 1000) * FrameDurationMs
    };

    WinrtVoipAudioDevice();
    virtual ~WinrtVoipAudioDevice();

    virtual ports::outbound::VoipAudioIoResult Open();
    virtual void Close();
    virtual ports::outbound::VoipAudioIoResult ReadFrame(std::vector<int16_t>* pcm, int timeoutMs);
    virtual ports::outbound::VoipAudioIoResult WriteFrame(const int16_t* pcm, size_t samples);
    virtual void SetMuted(bool muted);
    virtual void SetSpeaker(bool speakerOn);

private:
    HANDLE m_shutdownEvent;
    HANDLE m_captureEvent;
    HANDLE m_renderEvent;
    HANDLE m_captureThread;
    HANDLE m_renderThread;
    IAudioClient* m_captureClient;
    IAudioCaptureClient* m_captureService;
    IAudioClient* m_renderClient;
    IAudioRenderClient* m_renderService;
    bool m_open;
    bool m_muted;
    bool m_speakerOn;
    bool m_failed;

    std::mutex m_captureGate;
    std::condition_variable m_captureCv;
    std::deque<std::vector<int16_t>> m_captureFrames;
    std::vector<int16_t> m_captureScratch;

    std::mutex m_renderGate;
    std::deque<std::vector<int16_t>> m_renderFrames;
    std::vector<int16_t> m_renderScratch;

    static DWORD WINAPI CaptureThreadProc(void* arg);
    static DWORD WINAPI RenderThreadProc(void* arg);
    void CaptureLoop();
    void RenderLoop();
    ports::outbound::VoipAudioIoResult OpenCapture();
    ports::outbound::VoipAudioIoResult OpenRender();
    void PushCaptureSamples(const int16_t* samples, size_t sampleCount);
    void FillRenderSamples(int16_t* samples, size_t sampleCount);

    WinrtVoipAudioDevice(const WinrtVoipAudioDevice&);
    WinrtVoipAudioDevice& operator=(const WinrtVoipAudioDevice&);
};

class WinrtVoipAudioRuntimeFactory : public ports::outbound::IVoipAudioRuntimeFactory {
public:
    virtual bool IsAvailable(std::string* reason) const;
    virtual std::unique_ptr<ports::outbound::IVoipAudioDevice> CreateDevice();
    virtual std::unique_ptr<ports::outbound::IVoipAudioCodec> CreateCodec();
};

}}} // namespace vianigram::voip::infrastructure
