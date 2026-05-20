// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace ports { namespace outbound {

struct VoipAudioIoResult {
    bool Success;
    std::string Error;
    int SampleRate;
    int Channels;
    int FrameSamples;

    VoipAudioIoResult()
        : Success(false),
          SampleRate(0),
          Channels(0),
          FrameSamples(0) {}

    static VoipAudioIoResult Ok(int sampleRate, int channels, int frameSamples) {
        VoipAudioIoResult r;
        r.Success = true;
        r.SampleRate = sampleRate;
        r.Channels = channels;
        r.FrameSamples = frameSamples;
        return r;
    }

    static VoipAudioIoResult Fail(const std::string& error) {
        VoipAudioIoResult r;
        r.Success = false;
        r.Error = error;
        return r;
    }
};

class IVoipAudioDevice {
public:
    virtual ~IVoipAudioDevice() {}

    virtual VoipAudioIoResult Open() = 0;
    virtual void Close() = 0;

    virtual VoipAudioIoResult ReadFrame(std::vector<int16_t>* pcm, int timeoutMs) = 0;
    virtual VoipAudioIoResult WriteFrame(const int16_t* pcm, size_t samples) = 0;

    virtual void SetMuted(bool muted) = 0;
    virtual void SetSpeaker(bool speakerOn) = 0;
};

class IVoipAudioCodec {
public:
    virtual ~IVoipAudioCodec() {}

    virtual int Init(int bitrateBps) = 0;
    virtual int EncodeFrame(
        const int16_t* pcm,
        int pcmFrames,
        uint8_t* opusOut,
        size_t opusCapacity) = 0;
    virtual int DecodeFrame(
        const uint8_t* opusBytes,
        size_t opusLength,
        int16_t* pcmOut,
        int pcmCapacityFrames) = 0;
    virtual int DecodePlc(int16_t* pcmOut, int pcmCapacityFrames) = 0;
    virtual void Destroy() = 0;
    virtual bool Ready() const = 0;
};

class IVoipAudioRuntimeFactory {
public:
    virtual ~IVoipAudioRuntimeFactory() {}

    virtual bool IsAvailable(std::string* reason) const = 0;
    virtual std::unique_ptr<IVoipAudioDevice> CreateDevice() = 0;
    virtual std::unique_ptr<IVoipAudioCodec> CreateCodec() = 0;
};

}}}} // namespace vianigram::voip::ports::outbound
