// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "tgcalls_signaling_messages.h"

#include <cstdlib>
#include <cstring>
#include <sstream>

// Hand-written JSON parser and serializer for tgcalls v2 Signaling messages.
//
// The expected inputs come from a Telegram peer client that uses json11 to
// emit minified JSON. They are well-formed UTF-8 with at most ~32 KB of
// payload. We only need a flat (max 2 levels deep) walker:
//
//   Object  := { "key": Value (, "key": Value)* }
//   Array   := [ Value (, Value)* ]
//   Value   := String | Number | true | false | null | Object | Array
//
// We keep the parser intentionally small (no error recovery beyond bubbling
// failure up to the @type dispatch). Escape handling supports \" \\ / \n \r
// \t \b \f and \uXXXX (BMP only — Telegram never emits anything else here).

namespace vianigram { namespace voip { namespace domain {

namespace {

// ----- JSON value model ---------------------------------------------------

enum JsonKind {
    JsonKind_Null = 0,
    JsonKind_Bool = 1,
    JsonKind_Number = 2,
    JsonKind_String = 3,
    JsonKind_Array = 4,
    JsonKind_Object = 5
};

struct JsonValue {
    JsonKind Kind;
    bool BoolValue;
    double NumberValue;
    std::string StringValue;
    std::vector<JsonValue> ArrayValue;
    // Parallel-arrays object so we don't pull in <map> with non-default
    // allocators on Phone 8.1 toolchains.
    std::vector<std::string> ObjectKeys;
    std::vector<JsonValue> ObjectValues;

    JsonValue() : Kind(JsonKind_Null), BoolValue(false), NumberValue(0.0) {}

    const JsonValue* Find(const char* key) const {
        if (Kind != JsonKind_Object) return 0;
        size_t n = ObjectKeys.size();
        for (size_t i = 0; i < n; i++) {
            if (ObjectKeys[i] == key) return &ObjectValues[i];
        }
        return 0;
    }
};

// ----- Parser -------------------------------------------------------------

struct JsonParser {
    const char* Data;
    size_t Size;
    size_t Pos;
    bool Failed;

    JsonParser(const std::string& s) : Data(s.data()), Size(s.size()), Pos(0), Failed(false) {}

    void SkipWs() {
        while (Pos < Size) {
            char c = Data[Pos];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') Pos++;
            else break;
        }
    }

    char Peek() {
        if (Pos >= Size) { Failed = true; return '\0'; }
        return Data[Pos];
    }

    bool Match(char c) {
        SkipWs();
        if (Pos < Size && Data[Pos] == c) { Pos++; return true; }
        return false;
    }

    void Expect(char c) {
        if (!Match(c)) Failed = true;
    }

    bool ParseString(std::string& out) {
        SkipWs();
        if (Pos >= Size || Data[Pos] != '"') { Failed = true; return false; }
        Pos++;
        out.clear();
        while (Pos < Size) {
            char c = Data[Pos++];
            if (c == '"') return true;
            if (c == '\\') {
                if (Pos >= Size) { Failed = true; return false; }
                char e = Data[Pos++];
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        if (Pos + 4 > Size) { Failed = true; return false; }
                        unsigned cp = 0;
                        for (int i = 0; i < 4; i++) {
                            char h = Data[Pos++];
                            cp <<= 4;
                            if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                            else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                            else { Failed = true; return false; }
                        }
                        // Encode BMP code point as UTF-8.
                        if (cp < 0x80) {
                            out.push_back((char)cp);
                        } else if (cp < 0x800) {
                            out.push_back((char)(0xC0 | (cp >> 6)));
                            out.push_back((char)(0x80 | (cp & 0x3F)));
                        } else {
                            out.push_back((char)(0xE0 | (cp >> 12)));
                            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
                            out.push_back((char)(0x80 | (cp & 0x3F)));
                        }
                        break;
                    }
                    default: out.push_back(e); break;
                }
            } else {
                out.push_back(c);
            }
        }
        Failed = true;
        return false;
    }

    bool ParseLiteral(const char* lit) {
        size_t n = std::strlen(lit);
        if (Pos + n > Size) return false;
        if (std::memcmp(Data + Pos, lit, n) != 0) return false;
        Pos += n;
        return true;
    }

    bool ParseNumber(double& out) {
        SkipWs();
        size_t start = Pos;
        if (Pos < Size && (Data[Pos] == '-' || Data[Pos] == '+')) Pos++;
        bool sawDigit = false;
        while (Pos < Size && Data[Pos] >= '0' && Data[Pos] <= '9') { Pos++; sawDigit = true; }
        if (Pos < Size && Data[Pos] == '.') {
            Pos++;
            while (Pos < Size && Data[Pos] >= '0' && Data[Pos] <= '9') { Pos++; sawDigit = true; }
        }
        if (Pos < Size && (Data[Pos] == 'e' || Data[Pos] == 'E')) {
            Pos++;
            if (Pos < Size && (Data[Pos] == '-' || Data[Pos] == '+')) Pos++;
            while (Pos < Size && Data[Pos] >= '0' && Data[Pos] <= '9') Pos++;
        }
        if (!sawDigit) { Failed = true; return false; }
        std::string buf(Data + start, Pos - start);
        out = std::atof(buf.c_str());
        return true;
    }

    bool ParseValue(JsonValue& out) {
        SkipWs();
        if (Failed || Pos >= Size) { Failed = true; return false; }
        char c = Data[Pos];
        if (c == '"') {
            out.Kind = JsonKind_String;
            return ParseString(out.StringValue);
        }
        if (c == '{') {
            Pos++;
            out.Kind = JsonKind_Object;
            SkipWs();
            if (Match('}')) return true;
            while (true) {
                std::string key;
                if (!ParseString(key)) return false;
                SkipWs();
                Expect(':');
                if (Failed) return false;
                JsonValue v;
                if (!ParseValue(v)) return false;
                out.ObjectKeys.push_back(key);
                out.ObjectValues.push_back(v);
                SkipWs();
                if (Match(',')) continue;
                if (Match('}')) return true;
                Failed = true;
                return false;
            }
        }
        if (c == '[') {
            Pos++;
            out.Kind = JsonKind_Array;
            SkipWs();
            if (Match(']')) return true;
            while (true) {
                JsonValue v;
                if (!ParseValue(v)) return false;
                out.ArrayValue.push_back(v);
                SkipWs();
                if (Match(',')) continue;
                if (Match(']')) return true;
                Failed = true;
                return false;
            }
        }
        if (c == 't' && ParseLiteral("true"))  { out.Kind = JsonKind_Bool; out.BoolValue = true;  return true; }
        if (c == 'f' && ParseLiteral("false")) { out.Kind = JsonKind_Bool; out.BoolValue = false; return true; }
        if (c == 'n' && ParseLiteral("null"))  { out.Kind = JsonKind_Null; return true; }
        if (c == '-' || (c >= '0' && c <= '9')) {
            out.Kind = JsonKind_Number;
            return ParseNumber(out.NumberValue);
        }
        Failed = true;
        return false;
    }
};

bool ParseJson(const std::string& json, JsonValue& root) {
    JsonParser p(json);
    if (!p.ParseValue(root)) return false;
    return !p.Failed;
}

// ----- Helpers ------------------------------------------------------------

uint32_t NumberOrStringToUInt32(const JsonValue& v) {
    if (v.Kind == JsonKind_Number) {
        return (uint32_t)v.NumberValue;
    }
    if (v.Kind == JsonKind_String) {
        return (uint32_t)std::atoi(v.StringValue.c_str());
    }
    return 0;
}

std::string EscapeJson(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (size_t i = 0; i < in.size(); i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::sprintf(buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back((char)c);
                }
                break;
        }
    }
    return out;
}

std::string Uint32ToString(uint32_t v) {
    std::ostringstream s; s << v; return s.str();
}

// ----- Per-message-type parsers ------------------------------------------

bool ParseInitialSetup(const JsonValue& obj, InitialSetupMsg& out) {
    const JsonValue* ufrag = obj.Find("ufrag");
    const JsonValue* pwd = obj.Find("pwd");
    const JsonValue* fps = obj.Find("fingerprints");
    if (!ufrag || ufrag->Kind != JsonKind_String) return false;
    if (!pwd || pwd->Kind != JsonKind_String) return false;
    if (!fps || fps->Kind != JsonKind_Array) return false;
    out.Ufrag = ufrag->StringValue;
    out.Pwd = pwd->StringValue;
    const JsonValue* renomination = obj.Find("renomination");
    if (renomination && renomination->Kind == JsonKind_Bool) {
        out.SupportsRenomination = renomination->BoolValue;
    }
    if (!fps->ArrayValue.empty()) {
        const JsonValue& fp = fps->ArrayValue[0];
        if (fp.Kind == JsonKind_Object) {
            const JsonValue* h = fp.Find("hash");
            const JsonValue* s = fp.Find("setup");
            const JsonValue* f = fp.Find("fingerprint");
            if (h && h->Kind == JsonKind_String) out.Fingerprint.Hash = h->StringValue;
            if (s && s->Kind == JsonKind_String) out.Fingerprint.Setup = s->StringValue;
            if (f && f->Kind == JsonKind_String) out.Fingerprint.Fingerprint = f->StringValue;
        }
    }
    return true;
}

bool ParseCandidates(const JsonValue& obj, CandidatesMsg& out) {
    const JsonValue* arr = obj.Find("candidates");
    if (!arr || arr->Kind != JsonKind_Array) return false;
    for (size_t i = 0; i < arr->ArrayValue.size(); i++) {
        const JsonValue& item = arr->ArrayValue[i];
        if (item.Kind != JsonKind_Object) continue;
        const JsonValue* sdp = item.Find("sdpString");
        if (sdp && sdp->Kind == JsonKind_String) {
            IceCandidate c;
            c.SdpString = sdp->StringValue;
            out.Candidates.push_back(c);
        }
    }
    return true;
}

bool ParseConnection(const JsonValue& obj, ConnectionMsg& out) {
    const JsonValue* status = obj.Find("status");
    if (status && status->Kind == JsonKind_String) {
        out.Status = status->StringValue;
        return true;
    }
    return false;
}

bool ParsePingPong(const JsonValue& obj, uint32_t& outId) {
    const JsonValue* p = obj.Find("pingId");
    if (!p) p = obj.Find("ping_id");
    if (!p) return false;
    outId = NumberOrStringToUInt32(*p);
    return true;
}

bool ParseMediaState(const JsonValue& obj, MediaStateMsg& out) {
    const JsonValue* muted = obj.Find("muted");
    if (muted && muted->Kind == JsonKind_Bool) out.IsMuted = muted->BoolValue;
    const JsonValue* video = obj.Find("videoState");
    if (video && video->Kind == JsonKind_String) out.VideoState = video->StringValue;
    else out.VideoState = "inactive";
    const JsonValue* screen = obj.Find("screencastState");
    if (screen && screen->Kind == JsonKind_String) out.ScreencastState = screen->StringValue;
    else out.ScreencastState = "inactive";
    const JsonValue* rot = obj.Find("videoRotation");
    if (rot && rot->Kind == JsonKind_Number) out.VideoRotation = (int)rot->NumberValue;
    const JsonValue* low = obj.Find("lowBattery");
    if (low && low->Kind == JsonKind_Bool) out.LowBattery = low->BoolValue;
    return true;
}

// ----- Per-message-type serializers --------------------------------------

std::string SerializeInitialSetup(const InitialSetupMsg& m) {
    std::ostringstream s;
    s << "{\"@type\":\"InitialSetup\",\"ufrag\":\"" << EscapeJson(m.Ufrag)
      << "\",\"pwd\":\"" << EscapeJson(m.Pwd)
      << "\",\"renomination\":" << (m.SupportsRenomination ? "true" : "false")
      << ",\"fingerprints\":[{\"hash\":\"" << EscapeJson(m.Fingerprint.Hash)
      << "\",\"setup\":\"" << EscapeJson(m.Fingerprint.Setup)
      << "\",\"fingerprint\":\"" << EscapeJson(m.Fingerprint.Fingerprint)
      << "\"}]}";
    return s.str();
}

std::string SerializeCandidates(const CandidatesMsg& m) {
    std::ostringstream s;
    s << "{\"@type\":\"Candidates\",\"candidates\":[";
    for (size_t i = 0; i < m.Candidates.size(); i++) {
        if (i) s << ",";
        s << "{\"sdpString\":\"" << EscapeJson(m.Candidates[i].SdpString) << "\"}";
    }
    s << "]}";
    return s.str();
}

std::string SerializeConnection(const ConnectionMsg& m) {
    std::ostringstream s;
    s << "{\"@type\":\"Connection\",\"status\":\"" << EscapeJson(m.Status) << "\"}";
    return s.str();
}

std::string SerializePing(const PingMsg& m) {
    std::ostringstream s;
    s << "{\"@type\":\"Ping\",\"pingId\":" << m.PingId << "}";
    return s.str();
}

std::string SerializePong(const PongMsg& m) {
    std::ostringstream s;
    s << "{\"@type\":\"Pong\",\"pingId\":" << m.PingId << "}";
    return s.str();
}

std::string SerializeMediaState(const MediaStateMsg& m) {
    std::ostringstream s;
    s << "{\"@type\":\"MediaState\""
      << ",\"muted\":" << (m.IsMuted ? "true" : "false")
      << ",\"lowBattery\":" << (m.LowBattery ? "true" : "false")
      << ",\"videoState\":\"" << EscapeJson(m.VideoState.empty() ? std::string("inactive") : m.VideoState) << "\""
      << ",\"screencastState\":\"" << EscapeJson(m.ScreencastState.empty() ? std::string("inactive") : m.ScreencastState) << "\""
      << ",\"videoRotation\":" << m.VideoRotation
      << "}";
    return s.str();
}

} // anonymous namespace

TgcallsMessage TgcallsSignalingMessages::Parse(const std::string& json) {
    TgcallsMessage msg;
    msg.RawJson = json;

    JsonValue root;
    if (!ParseJson(json, root) || root.Kind != JsonKind_Object) {
        return msg;
    }

    const JsonValue* type = root.Find("@type");
    if (!type || type->Kind != JsonKind_String) {
        return msg;
    }
    msg.TypeName = type->StringValue;
    const std::string& t = type->StringValue;

    if (t == "InitialSetup") {
        if (ParseInitialSetup(root, msg.Initial)) {
            msg.Type = TgcallsMessageType_InitialSetup;
        }
    } else if (t == "Candidates") {
        if (ParseCandidates(root, msg.Candidates)) {
            msg.Type = TgcallsMessageType_Candidates;
        }
    } else if (t == "NegotiateChannels") {
        // Not yet decoded into structured form; surface as Unknown but tagged.
        msg.Type = TgcallsMessageType_NegotiateChannels;
    } else if (t == "Media") {
        msg.Type = TgcallsMessageType_Media;
    } else if (t == "MediaState") {
        if (ParseMediaState(root, msg.MediaState)) {
            msg.Type = TgcallsMessageType_MediaState;
        }
    } else if (t == "RemoteMediaState") {
        if (ParseMediaState(root, msg.MediaState)) {
            msg.Type = TgcallsMessageType_RemoteMediaState;
        }
    } else if (t == "Connection") {
        if (ParseConnection(root, msg.Connection)) {
            msg.Type = TgcallsMessageType_Connection;
        }
    } else if (t == "Ping") {
        if (ParsePingPong(root, msg.Ping.PingId)) {
            msg.Type = TgcallsMessageType_Ping;
        }
    } else if (t == "Pong") {
        if (ParsePingPong(root, msg.Pong.PingId)) {
            msg.Type = TgcallsMessageType_Pong;
        }
    } else if (t == "EmptyAck") {
        msg.Type = TgcallsMessageType_EmptyAck;
    }
    return msg;
}

std::string TgcallsSignalingMessages::Serialize(const TgcallsMessage& msg) {
    switch (msg.Type) {
        case TgcallsMessageType_InitialSetup: return SerializeInitialSetup(msg.Initial);
        case TgcallsMessageType_Candidates:   return SerializeCandidates(msg.Candidates);
        case TgcallsMessageType_Connection:   return SerializeConnection(msg.Connection);
        case TgcallsMessageType_Ping:         return SerializePing(msg.Ping);
        case TgcallsMessageType_Pong:         return SerializePong(msg.Pong);
        case TgcallsMessageType_MediaState:   return SerializeMediaState(msg.MediaState);
        default:
            // For unknown types fall back to RawJson if present (round-trip).
            return msg.RawJson;
    }
}

}}} // namespace vianigram::voip::domain
