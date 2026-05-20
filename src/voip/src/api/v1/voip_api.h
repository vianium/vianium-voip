// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

namespace Vianium { namespace VoIP {

public ref class VoipCapabilityResult sealed {
public:
    property bool CanExchangeCallKeys;
    property bool CanStartMedia;
    property Platform::String^ Reason;
};

public ref class VoipOperationResult sealed {
public:
    property bool Success;
    property int ErrorCode;
    property Platform::String^ ErrorMessage;
};

public ref class VoipDhMaterialResult sealed {
public:
    property bool Success;
    property int ErrorCode;
    property Platform::String^ ErrorMessage;
    property Platform::Array<uint8>^ PublicValue;
    property Platform::Array<uint8>^ PublicHash;
    property int64 KeyFingerprint;
    property Platform::String^ KeyHandle;
};

public ref class VoipMediaStatsResult sealed {
public:
    property Platform::String^ State;
    property int64 CallId;
    property bool Muted;
    property bool SpeakerOn;
    property Platform::String^ EndpointIp;
    property int EndpointPort;
    property float OutboundLevel;
    property float InboundLevel;
    property float PacketLossPercent;
    property int RttMs;
    property int BitrateBps;
    property int Underruns;
    property int64 PacketsSent;
    property int64 PacketsReceived;
    property int64 PacketsLost;
    property int64 BytesSent;
    property int64 BytesReceived;
};

public ref class VoipEndpointInfo sealed {
public:
    property int64 Id;
    property Platform::String^ Ip;
    property Platform::String^ Ipv6;
    property int Port;
    property Platform::Array<uint8>^ PeerTag;
    property Platform::String^ Kind;
    property bool Tcp;
    property bool Stun;
    property bool Turn;
    property Platform::String^ Username;
    property Platform::String^ Password;
    property int64 ReflectorId;
};

public ref class VoipCallStartDescriptor sealed {
public:
    property int64 CallId;
    property int64 AccessHash;
    property bool IsInitiator;
    property bool IsVideo;
    property bool UdpP2p;
    property bool UdpReflector;
    property int MinLayer;
    property int MaxLayer;
    property Platform::Array<Platform::String^>^ LibraryVersions;
    property int64 KeyFingerprint;
    property Platform::String^ KeyHandle;
    property Windows::Foundation::Collections::IVector<VoipEndpointInfo^>^ Endpoints;
    property Platform::String^ CallConfigJson;
};

public ref class VoipSignalingDataProducedEventArgs sealed {
public:
    property int64 CallId;
    property Platform::Array<uint8>^ Data;
};

public ref class VoipRuntime sealed {
public:
    VoipRuntime();

    event Windows::Foundation::EventHandler<VoipSignalingDataProducedEventArgs^>^
        SignalingDataProduced;

    VoipCapabilityResult^ GetCapability();

    Windows::Foundation::IAsyncOperation<VoipDhMaterialResult^>^
        CreateOutgoingDhAsync(int randomId, int g, const Platform::Array<uint8>^ p);

    VoipOperationResult^ BindOutgoingCall(int randomId, int64 callId);

    VoipOperationResult^ RegisterIncomingGAHash(int64 callId, const Platform::Array<uint8>^ gAHash);

    Windows::Foundation::IAsyncOperation<VoipDhMaterialResult^>^
        CreateIncomingDhAsync(int64 callId, int g, const Platform::Array<uint8>^ p);

    Windows::Foundation::IAsyncOperation<VoipDhMaterialResult^>^
        AcceptPeerGBAsync(int64 callId, const Platform::Array<uint8>^ gB);

    Windows::Foundation::IAsyncOperation<VoipOperationResult^>^
        ConfirmPeerGAOrBAsync(int64 callId, const Platform::Array<uint8>^ gAOrB, int64 expectedFingerprint);

    int64 GetLocalFingerprint(int64 callId);
    Platform::String^ GetKeyHandle(int64 callId);
    void DropCall(int64 callId);

    /// Diagnostic-only: returns the 256-byte DH shared key for the given
    /// call so the managed adapter can locally decrypt
    /// updatePhoneCallSignalingData blobs through TgcallsSignalingDiagnostics.
    /// Returns an empty array if the DH has not finished or the call has
    /// been dropped. Not part of the production media path.
    Platform::Array<uint8>^ GetSharedKeyDiagnosticBytes(int64 callId);

    Windows::Foundation::IAsyncOperation<VoipOperationResult^>^
        StartMediaAsync(
            int64 callId,
            Platform::String^ keyHandle,
            Windows::Foundation::Collections::IVector<VoipEndpointInfo^>^ endpoints);

    Windows::Foundation::IAsyncOperation<VoipOperationResult^>^
        StartCallAsync(VoipCallStartDescriptor^ descriptor);

    Windows::Foundation::IAsyncOperation<VoipOperationResult^>^
        ReceiveSignalingDataAsync(int64 callId, const Platform::Array<uint8>^ data);

    Windows::Foundation::IAsyncOperation<VoipOperationResult^>^
        StopMediaAsync();

    Windows::Foundation::IAsyncOperation<VoipOperationResult^>^
        SetMutedAsync(bool muted);

    Windows::Foundation::IAsyncOperation<VoipOperationResult^>^
        SetSpeakerAsync(bool on);

    VoipMediaStatsResult^ GetMediaStats();

private:
    void RaiseSignalingDataProduced(int64 callId, Platform::Array<uint8>^ data);
};

public ref class VoipSelfTestResult sealed {
public:
    property Platform::String^ Name;
    property bool Passed;
    property Platform::String^ Detail;
};

public ref class VoipSelfTest sealed {
public:
    static Windows::Foundation::Collections::IVector<VoipSelfTestResult^>^ RunAll();
};

public ref class TgcallsSignalingDiagnosticResult sealed {
public:
    property bool Success;
    property Platform::String^ Error;
    property uint32 Seq;
    property Platform::String^ PlaintextUtf8;     // first 1024 bytes if printable JSON
    property Platform::String^ PlaintextHex;      // first 64 bytes hex regardless
    property uint32 PlaintextLength;
};

public ref class TgcallsSignalingDiagnostics sealed {
public:
    static TgcallsSignalingDiagnosticResult^ Decrypt(
        const Platform::Array<uint8>^ sharedKey,
        bool isOutgoing,
        const Platform::Array<uint8>^ encryptedData);
};

public ref class TgcallsParsedMessage sealed {
public:
    property Platform::String^ TypeName;
    property Platform::String^ JsonContent;

    // Candidates
    property Windows::Foundation::Collections::IVector<Platform::String^>^ CandidateSdpStrings;

    // InitialSetup
    property Platform::String^ Ufrag;
    property Platform::String^ Pwd;
    property bool SupportsRenomination;
    property Platform::String^ FingerprintHash;
    property Platform::String^ FingerprintSetup;
    property Platform::String^ FingerprintHex;

    // Connection
    property Platform::String^ ConnectionStatus;

    // Ping / Pong
    property uint32 PingId;

    // MediaState / RemoteMediaState
    property bool IsMuted;
    property Platform::String^ VideoState;
    property Platform::String^ ScreencastState;
    property int32 VideoRotation;
    property bool LowBattery;
};

public ref class TgcallsSignalingPipeline sealed {
public:
    static Windows::Foundation::Collections::IVector<TgcallsParsedMessage^>^ DecryptAndParse(
        const Platform::Array<uint8>^ sharedKey,
        bool isOutgoing,
        const Platform::Array<uint8>^ bytes);

    static Platform::Array<uint8>^ EncryptInitialSetup(
        const Platform::Array<uint8>^ sharedKey,
        bool isOutgoing,
        uint32 outgoingSeq,
        Platform::String^ ufrag,
        Platform::String^ pwd,
        Platform::String^ fingerprintHash,
        Platform::String^ fingerprintSetup,
        Platform::String^ fingerprintHex);

    static Platform::Array<uint8>^ EncryptCandidates(
        const Platform::Array<uint8>^ sharedKey,
        bool isOutgoing,
        uint32 outgoingSeq,
        const Platform::Array<Platform::String^>^ sdpStrings);
};

// EcdsaP256Identity --- DTLS / tgcalls Signaling identity backed by the
// platform ECDsaP256Sha256 provider.  Generate() creates a fresh keypair
// plus a self-signed X.509 v3 cert; the SHA-256 fingerprint of the cert
// is the value tgcalls Signaling exchanges over the WebRTC SDP.
public ref class EcdsaP256Identity sealed {
public:
    // Generate a fresh P-256 keypair.  Returns nullptr if platform crypto is
    // unavailable.
    static EcdsaP256Identity^ Generate();

    // SHA-256 fingerprint of the self-signed X.509 cert,
    // formatted "AB:CD:EF:..." (uppercase, colon-separated).
    property Platform::String^ Sha256Fingerprint
    {
        Platform::String^ get();
    }

    // Self-signed X.509 v3 cert in DER format.
    property Platform::Array<uint8>^ X509Der
    {
        Platform::Array<uint8>^ get();
    }

    // Sign a 32-byte SHA-256 hash; returns DER ECDSA-Sig-Value.
    Platform::Array<uint8>^ SignSha256(const Platform::Array<uint8>^ hash);

    // Returns the public key as an uncompressed EC point: 0x04 || X || Y.
    Platform::Array<uint8>^ ExportPublicKeyUncompressed();

private:
    EcdsaP256Identity();
    ~EcdsaP256Identity();

    void EnsureCertCached();

    // Native opaque handle.
    void* m_native;
    Platform::String^ m_cachedFingerprint;
    Platform::Array<uint8>^ m_cachedDer;
};

// SRTP session for the SRTP_AES128_CM_HMAC_SHA1_80 profile (RFC 3711 +
// RFC 5764). Construct from the 60 bytes of keying material exported by
// DTLS-SRTP and the local role flag (true if we are the DTLS client, in
// which case our outgoing keys come from the client_write_* halves of the
// export).
public ref class SrtpSession sealed {
public:
    // 60 bytes = client_write_master_key (16) || server_write_master_key (16) ||
    //            client_write_master_salt (14) || server_write_master_salt (14)
    static SrtpSession^ Create(
        const Platform::Array<uint8>^ srtpKeyingMaterial,
        bool weAreClient);

    // Encrypts a complete plaintext RTP packet (header + payload).
    // Returns nullptr on malformed input.
    Platform::Array<uint8>^ EncryptOutgoing(
        const Platform::Array<uint8>^ rtpPacket);

    // Verifies the auth tag and decrypts an SRTP packet.
    // Returns nullptr on tag mismatch or short packet.
    Platform::Array<uint8>^ DecryptIncoming(
        const Platform::Array<uint8>^ srtpPacket);

private:
    SrtpSession();
    ~SrtpSession();

    // Native opaque handle (pair of SrtpEncryptParams: outgoing + incoming).
    void* m_state;
};

// Minimal ICE connectivity-check agent exposed to the managed adapter.
// Wraps vianigram::voip::application::IceAgent for use from C# tgcalls
// signaling code. The agent is single-threaded; the caller serializes
// access. See application/ice_agent.h for the full contract.
public ref class IceConnectivityAgent sealed {
public:
    static IceConnectivityAgent^ Create(
        bool weAreControlling,
        Platform::String^ localUfrag,
        Platform::String^ localPwd,
        Platform::String^ remoteUfrag,
        Platform::String^ remotePwd);

    // Add one peer SDP "candidate:..." line.
    void AddRemoteCandidateLine(Platform::String^ sdpLine);

    // Generate local "relay" candidate strings to advertise back to the peer.
    Platform::Array<Platform::String^>^ GenerateLocalCandidateLines(
        const Platform::Array<Platform::String^>^ reflectorIps,
        int reflectorPort);

    // The set of (target ip/port + STUN bytes) we should send right now.
    // After calling this, copy NextRemoteIps[i]/NextRemotePorts[i] alongside
    // NextRequestBytes[i] for transmission.
    void RebuildBindingRequests();
    property Platform::Array<Platform::String^>^ NextRemoteIps
    {
        Platform::Array<Platform::String^>^ get();
    }
    property Platform::Array<int>^ NextRemotePorts
    {
        Platform::Array<int>^ get();
    }
    // Each request payload is exposed as an IBuffer to avoid the
    // illegal-in-WinRT jagged-array shape (Array<Array<uint8>>).
    property Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IBuffer^>^ NextRequestBytes
    {
        Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IBuffer^>^ get();
    }

    // Process incoming STUN. Returns response bytes (zero-length array if
    // no response is required).
    Platform::Array<uint8>^ ProcessIncomingStun(
        Platform::String^ srcIp, int srcPort,
        const Platform::Array<uint8>^ bytes);

    property bool IsConnected { bool get(); }
    property Platform::String^ SelectedRemoteIp { Platform::String^ get(); }
    property int SelectedRemotePort { int get(); }

private:
    IceConnectivityAgent();
    ~IceConnectivityAgent();
    void* m_impl; // pinned vianigram::voip::application::IceAgent*

    Platform::Array<Platform::String^>^      m_nextIps;
    Platform::Array<int>^                    m_nextPorts;
    Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IBuffer^>^ m_nextBytes;
};

// Diagnostics: STUN test-vector verifier for self-tests. Returns true if
// our codec round-trips the RFC 5769 §2.1 short-credential request fixture
// (transaction ID, USERNAME, MI, FP all match expected bytes).
public ref class StunCodecDiagnostics sealed {
public:
    static bool VerifyRfc5769Sample();
};

}} // namespace Vianium::VoIP
