// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "datagram_socket_reflector_transport.h"

#include "../domain/voip_reflector_packet.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <queue>
#include <sstream>
#include <vector>
#include <ppltasks.h>

using namespace concurrency;
using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Networking;
using namespace Windows::Networking::Sockets;
using namespace Windows::Storage::Streams;

namespace vianigram { namespace voip { namespace infrastructure {

namespace {

std::wstring ToWideAscii(const std::string& s) {
    std::wstring out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        out.push_back(static_cast<wchar_t>(static_cast<unsigned char>(s[i])));
    }
    return out;
}

Platform::String^ PortToString(int port) {
    wchar_t wport[16];
    _snwprintf_s(wport, 16, _TRUNCATE, L"%d", port);
    return ref new Platform::String(wport);
}

std::string HResultMessage(const char* prefix, int hr) {
    std::ostringstream s;
    s << prefix << " hr=0x" << std::hex << (unsigned int)hr;
    return s.str();
}

std::vector<uint8_t> ToVector(const Platform::Array<uint8>^ bytes) {
    if (bytes == nullptr || bytes->Length == 0) return std::vector<uint8_t>();
    std::vector<uint8_t> out(bytes->Length);
    std::memcpy(&out[0], bytes->Data, bytes->Length);
    return out;
}

Platform::Array<uint8>^ ToArray(const std::vector<uint8_t>& bytes) {
    auto out = ref new Platform::Array<uint8>((unsigned int)bytes.size());
    if (!bytes.empty()) {
        std::memcpy(out->Data, &bytes[0], bytes.size());
    }
    return out;
}

bool MatchesPeerTag(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& peerTag) {
    if (peerTag.empty()) return true;
    if (peerTag.size() != domain::VoipReflectorPacketCodec::PeerTagBytes) return false;
    if (bytes.size() < peerTag.size()) return false;
    for (size_t i = 0; i < peerTag.size(); i++) {
        if (bytes[i] != peerTag[i]) return false;
    }
    return true;
}

} // namespace

class DatagramSocketReflectorSession : public ports::outbound::IVoipReflectorDatagramSession {
public:
    DatagramSocketReflectorSession()
        : m_socket(nullptr),
          m_outputStream(nullptr),
          m_hasToken(false),
          m_open(false) {}

    virtual ~DatagramSocketReflectorSession() {
        Close();
    }

    virtual ports::outbound::VoipReflectorDatagramResult Open(const domain::VoipEndpoint& endpoint) {
        if (m_open) {
            return ports::outbound::VoipReflectorDatagramResult::Ok(std::vector<uint8_t>(), 0);
        }
        if (endpoint.Port <= 0 || endpoint.Port > 65535) {
            return ports::outbound::VoipReflectorDatagramResult::Fail("reflector endpoint port is invalid");
        }
        std::string host = endpoint.Ip.empty() ? endpoint.Ipv6 : endpoint.Ip;
        if (host.empty()) {
            return ports::outbound::VoipReflectorDatagramResult::Fail("reflector endpoint address is missing");
        }

        try {
            m_socket = ref new DatagramSocket();
            m_token = m_socket->MessageReceived +=
                ref new TypedEventHandler<DatagramSocket^, DatagramSocketMessageReceivedEventArgs^>(
                    [this](DatagramSocket^, DatagramSocketMessageReceivedEventArgs^ args) {
                        try {
                            DataReader^ reader = args->GetDataReader();
                            unsigned int len = reader->UnconsumedBufferLength;
                            if (len == 0) return;

                            auto raw = ref new Platform::Array<uint8>(len);
                            reader->ReadBytes(raw);
                            std::vector<uint8_t> bytes = ToVector(raw);

                            {
                                std::lock_guard<std::mutex> lock(m_gate);
                                m_received.push(bytes);
                            }
                            m_cv.notify_one();
                        }
                        catch (...) {
                        }
                    });
            m_hasToken = true;

            create_task(m_socket->BindServiceNameAsync(ref new Platform::String(L""))).get();

            auto hostName = ref new HostName(ref new Platform::String(ToWideAscii(host).c_str()));
            m_outputStream = create_task(m_socket->GetOutputStreamAsync(
                hostName,
                PortToString(endpoint.Port))).get();

            m_open = true;
            return ports::outbound::VoipReflectorDatagramResult::Ok(std::vector<uint8_t>(), 0);
        }
        catch (Platform::Exception^ ex) {
            Close();
            return ports::outbound::VoipReflectorDatagramResult::Fail(
                HResultMessage("reflector UDP open failed", ex->HResult));
        }
        catch (const std::exception& ex) {
            Close();
            return ports::outbound::VoipReflectorDatagramResult::Fail(ex.what());
        }
        catch (...) {
            Close();
            return ports::outbound::VoipReflectorDatagramResult::Fail("reflector UDP open failed");
        }
    }

    virtual ports::outbound::VoipReflectorDatagramResult Send(const std::vector<uint8_t>& bytes) {
        if (!m_open || m_outputStream == nullptr) {
            return ports::outbound::VoipReflectorDatagramResult::Fail("reflector UDP session is not open");
        }
        if (bytes.empty()) {
            return ports::outbound::VoipReflectorDatagramResult::Fail("reflector UDP datagram is empty");
        }

        DataWriter^ writer = nullptr;
        try {
            writer = ref new DataWriter(m_outputStream);
            writer->WriteBytes(ToArray(bytes));
            m_lastSendAt = std::chrono::steady_clock::now();
            create_task(writer->StoreAsync()).get();
            try { writer->DetachStream(); } catch (...) {}
            return ports::outbound::VoipReflectorDatagramResult::Ok(std::vector<uint8_t>(), 0);
        }
        catch (Platform::Exception^ ex) {
            if (writer != nullptr) {
                try { writer->DetachStream(); } catch (...) {}
            }
            return ports::outbound::VoipReflectorDatagramResult::Fail(
                HResultMessage("reflector UDP send failed", ex->HResult));
        }
        catch (const std::exception& ex) {
            if (writer != nullptr) {
                try { writer->DetachStream(); } catch (...) {}
            }
            return ports::outbound::VoipReflectorDatagramResult::Fail(ex.what());
        }
        catch (...) {
            if (writer != nullptr) {
                try { writer->DetachStream(); } catch (...) {}
            }
            return ports::outbound::VoipReflectorDatagramResult::Fail("reflector UDP send failed");
        }
    }

    virtual ports::outbound::VoipReflectorDatagramResult Receive(
        const std::vector<uint8_t>& expectedPeerTag,
        int timeoutMs)
    {
        if (!m_open) {
            return ports::outbound::VoipReflectorDatagramResult::Fail("reflector UDP session is not open");
        }
        if (timeoutMs <= 0) timeoutMs = 1500;

        std::chrono::steady_clock::time_point deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);

        std::unique_lock<std::mutex> lock(m_gate);
        while (true) {
            size_t pending = m_received.size();
            for (size_t i = 0; i < pending; i++) {
                std::vector<uint8_t> datagram = m_received.front();
                m_received.pop();
                if (MatchesPeerTag(datagram, expectedPeerTag)) {
                    int rttMs = 0;
                    if (m_lastSendAt.time_since_epoch().count() != 0) {
                        rttMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - m_lastSendAt).count();
                    }
                    return ports::outbound::VoipReflectorDatagramResult::Ok(datagram, rttMs);
                }
                m_received.push(datagram);
            }

            if (m_cv.wait_until(lock, deadline) == std::cv_status::timeout) {
                return ports::outbound::VoipReflectorDatagramResult::Fail("reflector UDP receive timed out");
            }
        }
    }

    virtual void Close() {
        if (m_socket != nullptr) {
            if (m_hasToken) {
                try { m_socket->MessageReceived -= m_token; } catch (...) {}
                m_hasToken = false;
            }
            try { delete m_socket; } catch (...) {}
        }
        m_socket = nullptr;
        m_outputStream = nullptr;
        m_open = false;
        {
            std::lock_guard<std::mutex> lock(m_gate);
            std::queue<std::vector<uint8_t>> empty;
            std::swap(m_received, empty);
        }
    }

private:
    DatagramSocket^ m_socket;
    IOutputStream^ m_outputStream;
    EventRegistrationToken m_token;
    bool m_hasToken;
    bool m_open;
    std::mutex m_gate;
    std::condition_variable m_cv;
    std::queue<std::vector<uint8_t>> m_received;
    std::chrono::steady_clock::time_point m_lastSendAt;
};

ports::outbound::VoipReflectorProbeResult DatagramSocketReflectorTransport::ProbeSelfInfo(
    const domain::VoipEndpoint& endpoint,
    uint64_t queryId,
    int timeoutMs)
{
    if (endpoint.Port <= 0 || endpoint.Port > 65535) {
        return ports::outbound::VoipReflectorProbeResult::Fail("reflector endpoint port is invalid");
    }
    std::string host = endpoint.Ip.empty() ? endpoint.Ipv6 : endpoint.Ip;
    if (host.empty()) {
        return ports::outbound::VoipReflectorProbeResult::Fail("reflector endpoint address is missing");
    }
    if (timeoutMs <= 0) timeoutMs = 1500;

    domain::VoipReflectorPacketResult request =
        domain::VoipReflectorPacketCodec::BuildSelfInfoRequest(endpoint.PeerTag, queryId);
    if (!request.Success) {
        return ports::outbound::VoipReflectorProbeResult::Fail(request.Error);
    }

    DatagramSocket^ socket = nullptr;
    DataWriter^ writer = nullptr;
    try {
        socket = ref new DatagramSocket();

        std::mutex gate;
        std::condition_variable cv;
        bool completed = false;
        ports::outbound::VoipReflectorProbeResult result =
            ports::outbound::VoipReflectorProbeResult::Fail("reflector probe timed out");

        EventRegistrationToken token = socket->MessageReceived +=
            ref new TypedEventHandler<DatagramSocket^, DatagramSocketMessageReceivedEventArgs^>(
                [&](DatagramSocket^, DatagramSocketMessageReceivedEventArgs^ args) {
                    try {
                        DataReader^ reader = args->GetDataReader();
                        unsigned int len = reader->UnconsumedBufferLength;
                        if (len == 0) return;

                        auto raw = ref new Platform::Array<uint8>(len);
                        reader->ReadBytes(raw);
                        std::vector<uint8_t> bytes = ToVector(raw);
                        domain::VoipReflectorPacketResult parsed =
                            domain::VoipReflectorPacketCodec::ParseSelfInfoResponse(
                                bytes.empty() ? nullptr : &bytes[0],
                                bytes.size(),
                                endpoint.PeerTag);
                        if (!parsed.Success || parsed.SelfInfo.QueryId != queryId) return;

                        std::lock_guard<std::mutex> lock(gate);
                        result = ports::outbound::VoipReflectorProbeResult::Ok(parsed.SelfInfo, 0);
                        completed = true;
                        cv.notify_one();
                    }
                    catch (...) {
                    }
                });

        create_task(socket->BindServiceNameAsync(ref new Platform::String(L""))).get();

        auto hostName = ref new HostName(ref new Platform::String(ToWideAscii(host).c_str()));
        auto outputStream = create_task(socket->GetOutputStreamAsync(hostName, PortToString(endpoint.Port))).get();
        writer = ref new DataWriter(outputStream);
        writer->WriteBytes(ToArray(request.Bytes));

        auto started = std::chrono::steady_clock::now();
        create_task(writer->StoreAsync()).get();
        try { writer->DetachStream(); } catch (...) {}
        writer = nullptr;

        {
            std::unique_lock<std::mutex> lock(gate);
            if (!completed) {
                cv.wait_for(lock, std::chrono::milliseconds(timeoutMs), [&]() { return completed; });
            }
            if (completed && result.Success) {
                std::chrono::steady_clock::time_point ended = std::chrono::steady_clock::now();
                result.RttMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(ended - started).count();
            }
        }

        socket->MessageReceived -= token;
        delete socket;
        socket = nullptr;
        return result;
    }
    catch (Platform::Exception^ ex) {
        if (writer != nullptr) {
            try { writer->DetachStream(); } catch (...) {}
        }
        if (socket != nullptr) {
            try { delete socket; } catch (...) {}
        }
        return ports::outbound::VoipReflectorProbeResult::Fail(
            HResultMessage("reflector UDP probe failed", ex->HResult));
    }
    catch (const std::exception& ex) {
        if (writer != nullptr) {
            try { writer->DetachStream(); } catch (...) {}
        }
        if (socket != nullptr) {
            try { delete socket; } catch (...) {}
        }
        return ports::outbound::VoipReflectorProbeResult::Fail(ex.what());
    }
    catch (...) {
        if (writer != nullptr) {
            try { writer->DetachStream(); } catch (...) {}
        }
        if (socket != nullptr) {
            try { delete socket; } catch (...) {}
        }
        return ports::outbound::VoipReflectorProbeResult::Fail("reflector UDP probe failed");
    }
}

std::unique_ptr<ports::outbound::IVoipReflectorDatagramSession>
DatagramSocketReflectorTransport::CreateDatagramSession() {
    return std::unique_ptr<ports::outbound::IVoipReflectorDatagramSession>(
        new DatagramSocketReflectorSession());
}

// ===========================================================================
// Mode B: async push receive
// ===========================================================================
//
// Reflector wire format on port 1400 — both directions:
//
//     [16-byte peer_tag][inner payload]
//
// Outbound: prepend our peer_tag, send to reflector — the reflector
// matches on tag and forwards the inner payload to the peer who
// registered with the same tag.
//
// Inbound: reflector echoes our peer_tag, then the inner payload from
// the peer. We strip 16 bytes and deliver pure ICE/DTLS/SRTP to the
// callback.
//
// Reflector hello (port 1400 UDP, optional but typical — the official
// tgcalls ReflectorPort sends this every 500ms-10s to keep the NAT
// binding alive and let the reflector record our public address):
//
//     [16-byte peer_tag][12 x 0xFF][1 x 0xFE][3 x 0xFF][8-byte uint64=123]
//
// = 16 + 12 + 1 + 3 + 8 = 40 bytes.  Padded to 4-byte alignment.
//
// For the simple flow we don't need the hello packet — the reflector
// will record our address from the FIRST regular packet (an ICE STUN
// binding request) and start forwarding inbound traffic to us. The
// hello matters more for keepalive / NAT pinhole maintenance and is
// left to a follow-up.

struct DatagramSocketReflectorTransport::Session {
    std::string ReflectorIp;
    int ReflectorPort;
    std::vector<uint8_t> PeerTag;       // 16 bytes
    DatagramSocket^ Socket;
    IOutputStream^ OutputStream;
    AsyncReceiveCallback Callback;
    EventRegistrationToken MessageToken;
    bool HasToken;
    // Active gates the MessageReceived lambda. Atomic so the flip in
    // CloseSession() is visible to a concurrently-running lambda without
    // needing the sessions mutex on the hot read path.
    std::atomic<bool> Active;

    Session() : ReflectorPort(0), Socket(nullptr), OutputStream(nullptr),
                HasToken(false), Active(false) {}
};

DatagramSocketReflectorTransport::DatagramSocketReflectorTransport() {}

DatagramSocketReflectorTransport::~DatagramSocketReflectorTransport() {
    CloseSession();
}

domain::VoipError DatagramSocketReflectorTransport::OpenSession(
    const std::string& reflectorIp,
    int reflectorPort,
    const std::vector<uint8_t>& peerTag,
    AsyncReceiveCallback onPacket)
{
    if (peerTag.size() != 16) {
        return domain::VoipError::Of(
            domain::VoipErrorKind::InvalidArgument, 0,
            "peer_tag must be exactly 16 bytes");
    }
    if (reflectorPort <= 0 || reflectorPort > 65535) {
        return domain::VoipError::Of(
            domain::VoipErrorKind::InvalidArgument, 0,
            "reflector port out of range");
    }
    if (reflectorIp.empty()) {
        return domain::VoipError::Of(
            domain::VoipErrorKind::InvalidArgument, 0,
            "reflector ip is empty");
    }
    if (!onPacket) {
        return domain::VoipError::Of(
            domain::VoipErrorKind::InvalidArgument, 0,
            "async receive callback is null");
    }

    auto session = std::make_shared<Session>();
    session->ReflectorIp = reflectorIp;
    session->ReflectorPort = reflectorPort;
    session->PeerTag = peerTag;
    session->Callback = onPacket;
    session->Active.store(true, std::memory_order_release);

    DatagramSocket^ socket = nullptr;
    try {
        socket = ref new DatagramSocket();
    }
    catch (Platform::Exception^ ex) {
        return domain::VoipError::Of(
            domain::VoipErrorKind::TransportFailed, ex->HResult,
            "DatagramSocket construction failed");
    }

    // Wire the MessageReceived push callback BEFORE binding so we don't
    // lose the very first inbound packet.
    std::weak_ptr<Session> sessionWeak = session;
    try {
        session->MessageToken = socket->MessageReceived +=
            ref new TypedEventHandler<DatagramSocket^, DatagramSocketMessageReceivedEventArgs^>(
                [sessionWeak](DatagramSocket^, DatagramSocketMessageReceivedEventArgs^ args) {
                    auto sess = sessionWeak.lock();
                    if (!sess) return;
                    if (!sess->Active.load(std::memory_order_acquire)) return;
                    try {
                        DataReader^ reader = args->GetDataReader();
                        unsigned int len = reader->UnconsumedBufferLength;
                        // Need at least 16 bytes for the peer_tag echo.
                        if (len < 16) return;

                        auto raw = ref new Platform::Array<uint8>(len);
                        reader->ReadBytes(raw);

                        // Validate the peer_tag echo matches our session.
                        // The reference implementation only checks the
                        // first 12 bytes (tag minus the 4-byte randomTag
                        // suffix); we do the same to be permissive.
                        bool tagMatches = true;
                        size_t cmpLen = sess->PeerTag.size();
                        if (cmpLen > 12) cmpLen = 12;
                        for (size_t i = 0; i < cmpLen; i++) {
                            if (raw->Data[i] != sess->PeerTag[i]) {
                                tagMatches = false;
                                break;
                            }
                        }
                        if (!tagMatches) return;

                        // Strip the 16-byte peer_tag prefix.
                        std::vector<uint8_t> payload;
                        if (len > 16) {
                            payload.assign(raw->Data + 16, raw->Data + len);
                        }

                        if (sess->Callback) {
                            sess->Callback(sess->ReflectorIp, sess->ReflectorPort, payload);
                        }
                    }
                    catch (Platform::Exception^) {
                        // Swallow — a malformed packet shouldn't tear down
                        // the receive loop. Could add a Trace() here later.
                    }
                    catch (...) {
                    }
                });
        session->HasToken = true;
    }
    catch (Platform::Exception^ ex) {
        try { delete socket; } catch (...) {}
        return domain::VoipError::Of(
            domain::VoipErrorKind::TransportFailed, ex->HResult,
            "DatagramSocket MessageReceived registration failed");
    }

    // GetOutputStreamAsync establishes a virtual stream binding to the
    // remote endpoint; on WP8.1 this is the supported way to drive UDP
    // sends from a DatagramSocket without doing per-send hostname
    // resolution. The same socket still receives inbound datagrams via
    // the MessageReceived event registered above.
    try {
        auto host = ref new HostName(ref new Platform::String(
            ToWideAscii(reflectorIp).c_str()));
        IOutputStream^ outputStream = create_task(socket->GetOutputStreamAsync(
            host, PortToString(reflectorPort))).get();
        session->Socket = socket;
        session->OutputStream = outputStream;
    }
    catch (Platform::Exception^ ex) {
        if (session->HasToken) {
            try { socket->MessageReceived -= session->MessageToken; } catch (...) {}
            session->HasToken = false;
        }
        try { delete socket; } catch (...) {}
        return domain::VoipError::Of(
            domain::VoipErrorKind::TransportFailed, ex->HResult,
            "DatagramSocket GetOutputStreamAsync failed");
    }

    {
        std::lock_guard<std::mutex> lk(m_sessionsMutex);
        m_sessions.push_back(session);
    }

    return domain::VoipError::Ok();
}

domain::VoipError DatagramSocketReflectorTransport::SendThroughSession(
    const std::string& reflectorIp,
    int reflectorPort,
    const std::vector<uint8_t>& payload)
{
    std::shared_ptr<Session> session;
    {
        std::lock_guard<std::mutex> lk(m_sessionsMutex);
        for (size_t i = 0; i < m_sessions.size(); i++) {
            const std::shared_ptr<Session>& s = m_sessions[i];
            if (s->Active
                && s->ReflectorIp == reflectorIp
                && s->ReflectorPort == reflectorPort) {
                session = s;
                break;
            }
        }
    }
    if (!session) {
        return domain::VoipError::Of(
            domain::VoipErrorKind::InvalidArgument, 0,
            "no open async session for the requested reflector endpoint");
    }
    if (session->OutputStream == nullptr) {
        return domain::VoipError::Of(
            domain::VoipErrorKind::TransportFailed, 0,
            "async session output stream is null");
    }
    if (session->PeerTag.size() != 16) {
        return domain::VoipError::Of(
            domain::VoipErrorKind::InvalidArgument, 0,
            "session peer_tag is invalid");
    }

    // Build wrapped frame: [16-byte peer_tag][inner payload].
    std::vector<uint8_t> wrapped;
    wrapped.reserve(16 + payload.size());
    wrapped.insert(wrapped.end(), session->PeerTag.begin(), session->PeerTag.end());
    wrapped.insert(wrapped.end(), payload.begin(), payload.end());

    DataWriter^ writer = nullptr;
    try {
        writer = ref new DataWriter(session->OutputStream);
        writer->WriteBytes(ToArray(wrapped));
        create_task(writer->StoreAsync()).get();
        try { writer->DetachStream(); } catch (...) {}
        return domain::VoipError::Ok();
    }
    catch (Platform::Exception^ ex) {
        if (writer != nullptr) {
            try { writer->DetachStream(); } catch (...) {}
        }
        return domain::VoipError::Of(
            domain::VoipErrorKind::TransportFailed, ex->HResult,
            "async session SendThroughSession failed");
    }
    catch (...) {
        if (writer != nullptr) {
            try { writer->DetachStream(); } catch (...) {}
        }
        return domain::VoipError::Of(
            domain::VoipErrorKind::TransportFailed, 0,
            "async session SendThroughSession failed");
    }
}

void DatagramSocketReflectorTransport::CloseSession() {
    // Heap-corruption fix (live device test, May 4 2026):
    //
    // The MessageReceived lambda runs on a WinRT thread pool thread; it
    // captures std::weak_ptr<Session> and (when locked) accesses
    // sess->Active and sess->Callback. Previously we were:
    //   1) flipping Active=false on the shutdown thread, then
    //   2) detaching the MessageReceived handler, then
    //   3) overwriting sess->Callback = AsyncReceiveCallback() on the
    //      shutdown thread,
    // while the lambda may already have been past the Active check on the
    // worker thread and was about to call sess->Callback(...). Writing
    // std::function from one thread while another thread reads it is UB
    // and produces 0xC0000374 STATUS_HEAP_CORRUPTION on app exit (the
    // function destructor runs over a half-decoded vtable).
    //
    // Fixes:
    //   - Active is now std::atomic<bool>; the flip is visible to the
    //     lambda on next read with proper memory ordering.
    //   - We do NOT overwrite Callback. The Session shared_ptr is
    //     released here (drained leaves scope), but any in-flight lambda
    //     still holds a strong ref via .lock() — Session and Callback
    //     stay alive until that lambda returns. The new shared_ptr ref
    //     count drops to zero only after no callbacks are running, which
    //     is the actual safe time to destroy the Callback.
    //   - We still detach the MessageReceived event so NEW deliveries
    //     stop, and drop the Socket so its underlying handle is released
    //     after all in-flight lambdas exit.
    std::vector<std::shared_ptr<Session> > drained;
    {
        std::lock_guard<std::mutex> lk(m_sessionsMutex);
        drained.swap(m_sessions);
    }
    for (size_t i = 0; i < drained.size(); i++) {
        std::shared_ptr<Session>& s = drained[i];
        if (!s) continue;
        s->Active.store(false, std::memory_order_release);
        if (s->Socket != nullptr) {
            if (s->HasToken) {
                try { s->Socket->MessageReceived -= s->MessageToken; } catch (...) {}
                s->HasToken = false;
            }
            try { delete s->Socket; } catch (...) {}
            s->Socket = nullptr;
        }
        s->OutputStream = nullptr;
        // NOTE: deliberately not zeroing s->Callback — see header comment.
    }
}

}}} // namespace vianigram::voip::infrastructure
