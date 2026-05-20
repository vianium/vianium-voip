// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include "../ports/outbound/i_voip_audio_runtime.h"

#include <cstddef>
#include <cstdint>

struct OpusDecoder;
struct OpusEncoder;

namespace vianigram { namespace voip { namespace infrastructure {

class OpusVoipCodec : public ports::outbound::IVoipAudioCodec {
public:
    enum {
        SampleRate = 48000,
        Channels = 1,
        FrameDurationMs = 60,
        SamplesPerFrame = (SampleRate / 1000) * FrameDurationMs,
        DefaultBitrateBps = 24000,
        MaxPacketBytes = 400
    };

    OpusVoipCodec();
    ~OpusVoipCodec();

    virtual int Init(int bitrateBps);
    virtual int EncodeFrame(
        const int16_t* pcm,
        int pcmFrames,
        uint8_t* opusOut,
        size_t opusCapacity);
    virtual int DecodeFrame(
        const uint8_t* opusBytes,
        size_t opusLength,
        int16_t* pcmOut,
        int pcmCapacityFrames);
    virtual int DecodePlc(int16_t* pcmOut, int pcmCapacityFrames);
    void Reset();
    virtual void Destroy();
    virtual bool Ready() const;

private:
    OpusEncoder* m_encoder;
    OpusDecoder* m_decoder;

    OpusVoipCodec(const OpusVoipCodec&);
    OpusVoipCodec& operator=(const OpusVoipCodec&);
};

}}} // namespace vianigram::voip::infrastructure
