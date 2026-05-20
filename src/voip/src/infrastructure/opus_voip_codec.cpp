// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "opus_voip_codec.h"

#include <opus.h>

namespace vianigram { namespace voip { namespace infrastructure {

OpusVoipCodec::OpusVoipCodec()
    : m_encoder(nullptr),
      m_decoder(nullptr) {
}

OpusVoipCodec::~OpusVoipCodec() {
    Destroy();
}

int OpusVoipCodec::Init(int bitrateBps) {
    Destroy();
    if (bitrateBps <= 0) bitrateBps = DefaultBitrateBps;

    int encoderError = OPUS_OK;
    m_encoder = opus_encoder_create(
        SampleRate,
        Channels,
        OPUS_APPLICATION_VOIP,
        &encoderError);
    if (encoderError != OPUS_OK || m_encoder == nullptr) {
        Destroy();
        return encoderError == OPUS_OK ? OPUS_ALLOC_FAIL : encoderError;
    }

    int decoderError = OPUS_OK;
    m_decoder = opus_decoder_create(SampleRate, Channels, &decoderError);
    if (decoderError != OPUS_OK || m_decoder == nullptr) {
        Destroy();
        return decoderError == OPUS_OK ? OPUS_ALLOC_FAIL : decoderError;
    }

    int result = OPUS_OK;
    result = opus_encoder_ctl(m_encoder, OPUS_SET_BITRATE(bitrateBps));
    if (result != OPUS_OK) return result;
    result = opus_encoder_ctl(m_encoder, OPUS_SET_COMPLEXITY(5));
    if (result != OPUS_OK) return result;
    result = opus_encoder_ctl(m_encoder, OPUS_SET_INBAND_FEC(1));
    if (result != OPUS_OK) return result;
    result = opus_encoder_ctl(m_encoder, OPUS_SET_PACKET_LOSS_PERC(5));
    if (result != OPUS_OK) return result;
    result = opus_encoder_ctl(m_encoder, OPUS_SET_DTX(0));
    if (result != OPUS_OK) return result;
    result = opus_encoder_ctl(m_encoder, OPUS_SET_VBR(0));
    if (result != OPUS_OK) return result;
    result = opus_encoder_ctl(m_encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
    return result;
}

int OpusVoipCodec::EncodeFrame(
    const int16_t* pcm,
    int pcmFrames,
    uint8_t* opusOut,
    size_t opusCapacity)
{
    if (m_encoder == nullptr) return OPUS_INVALID_STATE;
    if (pcm == nullptr || opusOut == nullptr) return OPUS_BAD_ARG;
    if (pcmFrames <= 0 || opusCapacity == 0 || opusCapacity > 1500) return OPUS_BAD_ARG;

    return opus_encode(
        m_encoder,
        pcm,
        pcmFrames,
        opusOut,
        static_cast<opus_int32>(opusCapacity));
}

int OpusVoipCodec::DecodeFrame(
    const uint8_t* opusBytes,
    size_t opusLength,
    int16_t* pcmOut,
    int pcmCapacityFrames)
{
    if (m_decoder == nullptr) return OPUS_INVALID_STATE;
    if (pcmOut == nullptr || pcmCapacityFrames <= 0) return OPUS_BAD_ARG;
    if (opusBytes == nullptr || opusLength == 0) {
        return DecodePlc(pcmOut, pcmCapacityFrames);
    }
    if (opusLength > 1500) return OPUS_BAD_ARG;

    return opus_decode(
        m_decoder,
        opusBytes,
        static_cast<opus_int32>(opusLength),
        pcmOut,
        pcmCapacityFrames,
        0);
}

int OpusVoipCodec::DecodePlc(int16_t* pcmOut, int pcmCapacityFrames) {
    if (m_decoder == nullptr) return OPUS_INVALID_STATE;
    if (pcmOut == nullptr || pcmCapacityFrames <= 0) return OPUS_BAD_ARG;
    return opus_decode(m_decoder, nullptr, 0, pcmOut, pcmCapacityFrames, 0);
}

void OpusVoipCodec::Reset() {
    if (m_encoder != nullptr) {
        opus_encoder_ctl(m_encoder, OPUS_RESET_STATE);
    }
    if (m_decoder != nullptr) {
        opus_decoder_ctl(m_decoder, OPUS_RESET_STATE);
    }
}

void OpusVoipCodec::Destroy() {
    if (m_encoder != nullptr) {
        opus_encoder_destroy(m_encoder);
        m_encoder = nullptr;
    }
    if (m_decoder != nullptr) {
        opus_decoder_destroy(m_decoder);
        m_decoder = nullptr;
    }
}

bool OpusVoipCodec::Ready() const {
    return m_encoder != nullptr && m_decoder != nullptr;
}

}}} // namespace vianigram::voip::infrastructure
