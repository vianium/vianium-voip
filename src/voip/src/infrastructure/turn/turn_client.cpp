// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "turn_client.h"

#include <vianium/crypto/random.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <ppltasks.h>
#include <sstream>
#include <windows.h>

using namespace concurrency;
using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Networking;
using namespace Windows::Networking::Sockets;
using namespace Windows::Storage::Streams;

namespace vianigram { namespace voip { namespace infrastructure { namespace turn {

namespace {

void Trace(const std::string& line) {
    std::string out = "[TurnClient] " + line + "\n";
    ::OutputDebugStringA(out.c_str());
}

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

Platform::Array<uint8>^ ToArray(const std::vector<uint8_t>& bytes) {
    auto out = ref new Platform::Array<uint8>(static_cast<unsigned int>(bytes.size()));
    if (!bytes.empty()) {
        std::memcpy(out->Data, &bytes[0], bytes.size());
    }
    return out;
}

bool TxnIdEquals(const uint8_t a[12], const uint8_t b[12]) {
    for (int i = 0; i < 12; i++) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

domain::VoipError MakeInvalid(const std::string& message) {
    return domain::VoipError::Of(
        domain::VoipErrorKind::InvalidArgument, 0, message.c_str());
}

domain::VoipError MakeTransportFailed(const std::string& message, int hr = 0) {
    return domain::VoipError::Of(
        domain::VoipErrorKind::TransportFailed, hr, message.c_str());
}

domain::VoipError MakeHandshakeTimeout(const std::string& message) {
    return domain::VoipError::Of(
        domain::VoipErrorKind::HandshakeTimeout, 0, message.c_str());
}

} // anonymous namespace

// =============================================================================
// SocketState --- shared with the MessageReceived lambda via weak_ptr so a
// teardown that flips Active=false is visible without overlapping the
// shared_ptr / std::function destruction. Same pattern as the heap-corruption
// fix in DatagramSocketReflectorTransport (see its CloseSession comment).
// =============================================================================

struct TurnClient::SocketState {
    DatagramSocket^ Socket;
    IOutputStream^  OutputStream;
    EventRegistrationToken Token;
    bool HasToken;
    std::atomic<bool> Active;
    TurnClient* Owner;          // raw -- guarded by Active.

    SocketState() : Socket(nullptr), OutputStream(nullptr),
                    HasToken(false), Active(false), Owner(NULL) {}
};

// =============================================================================
// Construction / destruction.
// =============================================================================

TurnClient::TurnClient()
    : m_active(false)
    , m_allocated(false)
    , m_reflectorPort(0)
    , m_havePending(false)
    , m_pendingComplete(false)
{
    std::memset(m_pendingTxnId, 0, sizeof(m_pendingTxnId));
}

TurnClient::~TurnClient() {
    Close();
}

// =============================================================================
// Close --- detach handlers, release socket. Idempotent. Same teardown
// discipline as DatagramSocketReflectorTransport: flip Active=false BEFORE
// detaching MessageReceived, do not overwrite std::function on the shutdown
// thread (the in-flight lambda may still be reading it on a worker thread).
// =============================================================================

void TurnClient::Close() {
    bool wasActive = m_active.exchange(false, std::memory_order_acq_rel);
    if (!wasActive) return;

    std::shared_ptr<SocketState> sock;
    {
        std::lock_guard<std::mutex> lk(m_lock);
        sock = m_socketState;
        m_socketState.reset();
        m_allocated.store(false, std::memory_order_release);
        m_havePending = false;
    }

    // Wake any thread blocked in WaitForResponse so it can observe the
    // Active=false flip and abort.
    m_pendingCv.notify_all();

    if (sock) {
        sock->Active.store(false, std::memory_order_release);
        if (sock->Socket != nullptr) {
            if (sock->HasToken) {
                try { sock->Socket->MessageReceived -= sock->Token; } catch (...) {}
                sock->HasToken = false;
            }
            try { delete sock->Socket; } catch (...) {}
            sock->Socket = nullptr;
        }
        sock->OutputStream = nullptr;
        // Do not zero sock->Owner -- in-flight lambdas may still need to
        // bail out via Active=false; the shared_ptr keeps SocketState alive
        // until the last lambda returns, at which point everything destructs
        // safely.
    }
    Trace("Close completed");
}

// =============================================================================
// OpenAllocation --- the synchronous handshake driver.
// =============================================================================

domain::VoipError TurnClient::OpenAllocation(
    const std::string& reflectorIp, int reflectorPort,
    const std::string& username, const std::string& password,
    const std::vector<TurnAddress>& peerAddresses,
    DataCallback onDataIndication)
{
    if (m_active.load(std::memory_order_acquire)) {
        return MakeInvalid("TurnClient already open");
    }
    if (reflectorIp.empty()) return MakeInvalid("reflectorIp is empty");
    if (reflectorPort <= 0 || reflectorPort > 65535) return MakeInvalid("reflectorPort out of range");
    if (username.empty()) return MakeInvalid("TURN username is empty");
    if (password.empty()) return MakeInvalid("TURN password is empty");

    {
        std::lock_guard<std::mutex> lk(m_lock);
        m_reflectorIp = reflectorIp;
        m_reflectorPort = reflectorPort;
        m_username = username;
        m_password = password;
        m_onData = onDataIndication;
        m_permittedPeers.clear();
        m_realm.clear();
        m_nonce.clear();
        m_key.clear();
        m_relayed = TurnAddress();
        m_havePending = false;
        m_pendingComplete = false;
    }

    auto sock = std::make_shared<SocketState>();
    sock->Owner = this;
    sock->Active.store(true, std::memory_order_release);

    DatagramSocket^ socket = nullptr;
    try {
        socket = ref new DatagramSocket();
    } catch (Platform::Exception^ ex) {
        return MakeTransportFailed("DatagramSocket ctor failed", ex->HResult);
    }

    std::weak_ptr<SocketState> weak = sock;
    try {
        sock->Token = socket->MessageReceived +=
            ref new TypedEventHandler<DatagramSocket^,
                                      DatagramSocketMessageReceivedEventArgs^>(
                [weak](DatagramSocket^, DatagramSocketMessageReceivedEventArgs^ args) {
                    auto state = weak.lock();
                    if (!state) return;
                    if (!state->Active.load(std::memory_order_acquire)) return;
                    try {
                        DataReader^ reader = args->GetDataReader();
                        unsigned int len = reader->UnconsumedBufferLength;
                        if (len == 0) return;

                        auto raw = ref new Platform::Array<uint8>(len);
                        reader->ReadBytes(raw);
                        std::vector<uint8_t> bytes(raw->Data, raw->Data + len);

                        // Re-check Active before invoking owner -- the
                        // shutdown thread may have flipped it between the
                        // weak.lock() above and now.
                        if (!state->Active.load(std::memory_order_acquire)) return;
                        TurnClient* owner = state->Owner;
                        if (owner == NULL) return;
                        owner->OnInboundUdp(bytes);
                    } catch (Platform::Exception^) {
                        // Swallow malformed datagrams.
                    } catch (...) {
                    }
                });
        sock->HasToken = true;
    } catch (Platform::Exception^ ex) {
        try { delete socket; } catch (...) {}
        return MakeTransportFailed("MessageReceived registration failed", ex->HResult);
    }

    try {
        auto host = ref new HostName(ref new Platform::String(
            ToWideAscii(reflectorIp).c_str()));
        IOutputStream^ outputStream = create_task(socket->GetOutputStreamAsync(
            host, PortToString(reflectorPort))).get();
        sock->Socket = socket;
        sock->OutputStream = outputStream;
    } catch (Platform::Exception^ ex) {
        if (sock->HasToken) {
            try { socket->MessageReceived -= sock->Token; } catch (...) {}
            sock->HasToken = false;
        }
        try { delete socket; } catch (...) {}
        return MakeTransportFailed("GetOutputStreamAsync failed", ex->HResult);
    }

    {
        std::lock_guard<std::mutex> lk(m_lock);
        m_socketState = sock;
    }
    m_active.store(true, std::memory_order_release);

    {
        std::ostringstream s;
        s << "OpenAllocation socket bound -> " << reflectorIp << ":" << reflectorPort
          << " username='" << username << "' password_len=" << password.size();
        Trace(s.str());
    }

    domain::VoipError handshake = DoAllocateHandshake();
    if (!handshake.IsOk()) {
        Trace(std::string("Allocate handshake failed: ") + handshake.Message);
        Close();
        return handshake;
    }

    // CreatePermission for any peer addresses that were known up front.
    if (!peerAddresses.empty()) {
        domain::VoipError perm = SendCreatePermission(peerAddresses);
        if (!perm.IsOk()) {
            Trace(std::string("Initial CreatePermission failed: ") + perm.Message);
            // Continue anyway -- the call site can retry later via
            // AddPeerPermission once additional candidates arrive.
        } else {
            std::lock_guard<std::mutex> lk(m_lock);
            for (size_t i = 0; i < peerAddresses.size(); i++) {
                m_permittedPeers.push_back(peerAddresses[i]);
            }
        }
    }

    return domain::VoipError::Ok();
}

// =============================================================================
// DoAllocateHandshake --- two-step Allocate: 401 challenge then authed.
// =============================================================================

domain::VoipError TurnClient::DoAllocateHandshake() {
    // ---- Step 1: unauthenticated Allocate ---------------------------------
    uint8_t txnId[12];
    GenerateTxnId(txnId);

    std::vector<uint8_t> req = EncodeAllocate(
        txnId, /*lifetimeSeconds=*/600,
        /*username=*/"", /*realm=*/"",
        /*nonce=*/std::vector<uint8_t>(),
        /*key=*/std::vector<uint8_t>());

    {
        std::lock_guard<std::mutex> lk(m_lock);
        m_havePending = true;
        m_pendingComplete = false;
        std::memcpy(m_pendingTxnId, txnId, 12);
        m_pendingResponse = TurnMessage();
    }

    {
        std::ostringstream s;
        s << "Allocate#1 (no auth) -> " << m_reflectorIp << ":" << m_reflectorPort
          << " bytes=" << req.size();
        Trace(s.str());
    }

    domain::VoipError sent = SendRawDatagram(req);
    if (!sent.IsOk()) return sent;

    TurnMessage response;
    if (!WaitForResponse(txnId, /*timeoutMs=*/2500, response)) {
        return MakeHandshakeTimeout("Allocate#1 timed out (no 401 challenge)");
    }

    if (TurnClassOf(response.Type) != kClassError) {
        // Some servers may grant Allocate without auth (rare). If we got
        // a Success straight away, take it.
        if (TurnClassOf(response.Type) == kClassSuccess && response.HasXorRelayed) {
            std::lock_guard<std::mutex> lk(m_lock);
            m_relayed = response.XorRelayed;
            m_allocated.store(true, std::memory_order_release);
            std::ostringstream s;
            s << "Allocate#1 unexpectedly accepted; relayed="
              << FormatAddress(m_relayed);
            Trace(s.str());
            return domain::VoipError::Ok();
        }
        std::ostringstream s;
        s << "Allocate#1 unexpected reply class=0x" << std::hex
          << TurnClassOf(response.Type);
        return MakeTransportFailed(s.str());
    }
    if (response.ErrorCode != 401 || !response.HasRealm || !response.HasNonce) {
        std::ostringstream s;
        s << "Allocate#1 401 missing REALM/NONCE (got code=" << response.ErrorCode
          << " realm=" << (response.HasRealm ? "yes" : "no")
          << " nonce=" << (response.HasNonce ? "yes" : "no") << ")";
        return MakeTransportFailed(s.str());
    }

    {
        std::lock_guard<std::mutex> lk(m_lock);
        m_realm = response.Realm;
        m_nonce = response.Nonce;
        m_key = DeriveLongTermKey(m_username, m_realm, m_password);
        std::ostringstream s;
        s << "Allocate#1 401 realm='" << m_realm
          << "' nonce_len=" << m_nonce.size()
          << " key_len=" << m_key.size();
        Trace(s.str());
    }

    // ---- Step 2: authenticated Allocate -----------------------------------
    GenerateTxnId(txnId);
    {
        std::lock_guard<std::mutex> lk(m_lock);
        m_havePending = true;
        m_pendingComplete = false;
        std::memcpy(m_pendingTxnId, txnId, 12);
        m_pendingResponse = TurnMessage();
    }

    std::vector<uint8_t> authedReq;
    {
        std::lock_guard<std::mutex> lk(m_lock);
        authedReq = EncodeAllocate(
            txnId, /*lifetimeSeconds=*/600,
            m_username, m_realm, m_nonce, m_key);
    }

    {
        std::ostringstream s;
        s << "Allocate#2 (authed) -> " << m_reflectorIp << ":" << m_reflectorPort
          << " bytes=" << authedReq.size();
        Trace(s.str());
    }

    domain::VoipError sent2 = SendRawDatagram(authedReq);
    if (!sent2.IsOk()) return sent2;

    TurnMessage response2;
    if (!WaitForResponse(txnId, /*timeoutMs=*/2500, response2)) {
        return MakeHandshakeTimeout("Allocate#2 timed out (no 200 OK)");
    }

    if (TurnClassOf(response2.Type) == kClassError) {
        std::ostringstream s;
        s << "Allocate#2 error code=" << response2.ErrorCode
          << " reason='" << response2.ErrorReason << "'";
        return MakeTransportFailed(s.str());
    }
    if (TurnClassOf(response2.Type) != kClassSuccess) {
        std::ostringstream s;
        s << "Allocate#2 unexpected class=0x" << std::hex
          << TurnClassOf(response2.Type);
        return MakeTransportFailed(s.str());
    }
    if (!response2.HasXorRelayed) {
        return MakeTransportFailed("Allocate#2 success missing XOR-RELAYED-ADDRESS");
    }

    {
        std::lock_guard<std::mutex> lk(m_lock);
        m_relayed = response2.XorRelayed;
        m_allocated.store(true, std::memory_order_release);
    }
    {
        std::ostringstream s;
        s << "Allocate -> 200 OK relayed=" << FormatAddress(response2.XorRelayed);
        if (response2.HasXorMapped) {
            s << " mapped=" << FormatAddress(response2.XorMapped);
        }
        if (response2.HasLifetime) {
            s << " lifetime=" << response2.Lifetime << "s";
        }
        Trace(s.str());
    }
    return domain::VoipError::Ok();
}

// =============================================================================
// SendCreatePermission --- bundles all peers in a single CreatePermission
// (RFC 5766 Section 9.1 allows multiple XOR-PEER-ADDRESS attributes).
// =============================================================================

domain::VoipError TurnClient::SendCreatePermission(
    const std::vector<TurnAddress>& peers)
{
    if (!m_allocated.load(std::memory_order_acquire)) {
        return MakeInvalid("CreatePermission before Allocate");
    }
    if (peers.empty()) return domain::VoipError::Ok();

    uint8_t txnId[12];
    GenerateTxnId(txnId);

    std::vector<uint8_t> req;
    {
        std::lock_guard<std::mutex> lk(m_lock);
        req = EncodeCreatePermission(txnId, peers,
            m_username, m_realm, m_nonce, m_key);
        m_havePending = true;
        m_pendingComplete = false;
        std::memcpy(m_pendingTxnId, txnId, 12);
        m_pendingResponse = TurnMessage();
    }

    {
        std::ostringstream s;
        s << "CreatePermission for " << peers.size() << " peer(s) -> "
          << m_reflectorIp << ":" << m_reflectorPort
          << " bytes=" << req.size();
        for (size_t i = 0; i < peers.size(); i++) {
            s << " peer[" << i << "]=" << FormatAddress(peers[i]);
        }
        Trace(s.str());
    }

    domain::VoipError sent = SendRawDatagram(req);
    if (!sent.IsOk()) return sent;

    TurnMessage response;
    if (!WaitForResponse(txnId, /*timeoutMs=*/2500, response)) {
        return MakeHandshakeTimeout("CreatePermission timed out");
    }

    if (TurnClassOf(response.Type) == kClassError) {
        std::ostringstream s;
        s << "CreatePermission error code=" << response.ErrorCode
          << " reason='" << response.ErrorReason << "'";
        return MakeTransportFailed(s.str());
    }
    if (TurnClassOf(response.Type) != kClassSuccess) {
        std::ostringstream s;
        s << "CreatePermission unexpected class=0x" << std::hex
          << TurnClassOf(response.Type);
        return MakeTransportFailed(s.str());
    }
    Trace("CreatePermission OK");
    return domain::VoipError::Ok();
}

domain::VoipError TurnClient::AddPeerPermission(const TurnAddress& peer) {
    if (!m_allocated.load(std::memory_order_acquire)) {
        return MakeInvalid("AddPeerPermission before Allocate");
    }

    // De-duplicate: if we've already permitted this address, this is a noop.
    {
        std::lock_guard<std::mutex> lk(m_lock);
        for (size_t i = 0; i < m_permittedPeers.size(); i++) {
            const TurnAddress& p = m_permittedPeers[i];
            if (p.Family == peer.Family && p.Port == peer.Port &&
                p.Address.size() == peer.Address.size() &&
                std::memcmp(p.Address.empty() ? NULL : &p.Address[0],
                            peer.Address.empty() ? NULL : &peer.Address[0],
                            p.Address.size()) == 0) {
                return domain::VoipError::Ok();
            }
        }
    }

    std::vector<TurnAddress> just_one;
    just_one.push_back(peer);
    domain::VoipError sent = SendCreatePermission(just_one);
    if (sent.IsOk()) {
        std::lock_guard<std::mutex> lk(m_lock);
        m_permittedPeers.push_back(peer);
    }
    return sent;
}

// =============================================================================
// Send --- wrap inner bytes in Send Indication and ship.
// =============================================================================

domain::VoipError TurnClient::Send(const TurnAddress& peer,
                                   const std::vector<uint8_t>& bytes)
{
    if (!m_allocated.load(std::memory_order_acquire)) {
        return MakeInvalid("Send before Allocate");
    }
    if (peer.Address.empty()) return MakeInvalid("Send peer address empty");

    uint8_t txnId[12];
    GenerateTxnId(txnId);

    std::vector<uint8_t> envelope = EncodeSendIndication(txnId, peer, bytes);
    return SendRawDatagram(envelope);
}

// =============================================================================
// SendRawDatagram --- single-shot UDP write. Caller has already framed the
// payload as either a STUN/TURN request or indication.
// =============================================================================

domain::VoipError TurnClient::SendRawDatagram(const std::vector<uint8_t>& bytes) {
    std::shared_ptr<SocketState> sock;
    {
        std::lock_guard<std::mutex> lk(m_lock);
        sock = m_socketState;
    }
    if (!sock || !sock->Active.load(std::memory_order_acquire) ||
        sock->OutputStream == nullptr) {
        return MakeTransportFailed("TurnClient socket not open");
    }
    if (bytes.empty()) return MakeInvalid("SendRawDatagram empty payload");

    DataWriter^ writer = nullptr;
    try {
        writer = ref new DataWriter(sock->OutputStream);
        writer->WriteBytes(ToArray(bytes));
        create_task(writer->StoreAsync()).get();
        try { writer->DetachStream(); } catch (...) {}
        return domain::VoipError::Ok();
    } catch (Platform::Exception^ ex) {
        if (writer != nullptr) { try { writer->DetachStream(); } catch (...) {} }
        return MakeTransportFailed("StoreAsync failed", ex->HResult);
    } catch (...) {
        if (writer != nullptr) { try { writer->DetachStream(); } catch (...) {} }
        return MakeTransportFailed("StoreAsync failed");
    }
}

// =============================================================================
// OnInboundUdp --- routed by the MessageReceived lambda. Either it's a
// reply to a synchronous Allocate / CreatePermission / Refresh request (in
// which case we signal m_pendingCv), or it's a Data Indication carrying
// inbound peer payload (in which case we strip and deliver to onData).
// =============================================================================

void TurnClient::OnInboundUdp(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return;
    if (!LooksLikeStunOrTurn(&bytes[0], bytes.size())) {
        // Not a STUN/TURN frame. Ignore -- a properly-configured TURN
        // server should never send anything else to us.
        return;
    }

    TurnMessage msg;
    if (!DecodeMessage(bytes, &msg)) {
        Trace("OnInboundUdp DecodeMessage failed");
        return;
    }

    uint16_t method = TurnMethodOf(msg.Type);
    uint16_t cls    = TurnClassOf(msg.Type);

    if (cls == kClassIndication && method == kMethodData) {
        // Server-to-client Data Indication. Deliver inner DATA bytes.
        DataCallback cb;
        std::string srcIp; int srcPort = 0;
        {
            std::lock_guard<std::mutex> lk(m_lock);
            cb = m_onData;
        }
        if (!msg.HasData || msg.Data.empty()) {
            Trace("Data Indication with no DATA attribute");
            return;
        }
        if (!msg.XorPeers.empty()) {
            const TurnAddress& src = msg.XorPeers[0];
            if (src.Family == kFamilyIPv4 && src.Address.size() == 4) {
                std::ostringstream s;
                s << static_cast<int>(src.Address[0]) << "."
                  << static_cast<int>(src.Address[1]) << "."
                  << static_cast<int>(src.Address[2]) << "."
                  << static_cast<int>(src.Address[3]);
                srcIp = s.str();
                srcPort = src.Port;
            }
        }
        if (cb) {
            cb(srcIp, srcPort, msg.Data);
        }
        return;
    }

    // Otherwise it's a response to one of our pending requests.
    if (cls != kClassSuccess && cls != kClassError) {
        // Server-side request? In long-term-cred TURN we never get those.
        return;
    }

    {
        std::lock_guard<std::mutex> lk(m_lock);
        if (!m_havePending) return;
        if (!TxnIdEquals(msg.TransactionId, m_pendingTxnId)) return;
        m_pendingResponse = msg;
        m_pendingComplete = true;
    }
    m_pendingCv.notify_all();
}

// =============================================================================
// WaitForResponse --- blocks the calling thread up to `timeoutMs` ms for the
// pending response keyed by `txnId` to arrive (set by OnInboundUdp).
// =============================================================================

bool TurnClient::WaitForResponse(const uint8_t txnId[12], int timeoutMs,
                                 TurnMessage& out)
{
    std::unique_lock<std::mutex> lk(m_lock);
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeoutMs);
    while (m_active.load(std::memory_order_acquire)) {
        if (m_pendingComplete &&
            m_havePending &&
            TxnIdEquals(m_pendingTxnId, txnId)) {
            out = m_pendingResponse;
            m_havePending = false;
            m_pendingComplete = false;
            return true;
        }
        if (m_pendingCv.wait_until(lk, deadline) == std::cv_status::timeout) {
            return false;
        }
    }
    return false;
}

// =============================================================================
// GenerateTxnId --- 12 random bytes via Vianium.Core.Tls / WinRT crypto.
// =============================================================================

void TurnClient::GenerateTxnId(uint8_t out[12]) {
    vianium::crypto::GenerateRandom(out, 12);
}

// =============================================================================
// Accessors.
// =============================================================================

TurnAddress TurnClient::RelayedAddress() const {
    std::lock_guard<std::mutex> lk(m_lock);
    return m_relayed;
}

}}}} // namespace vianigram::voip::infrastructure::turn
