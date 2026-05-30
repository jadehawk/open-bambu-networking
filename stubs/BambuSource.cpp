// libBambuSource.so: LAN-only video source for Bambu Lab printers, as
// consumed by Bambu Studio's `gstbambusrc` element.
//
// Bambu Studio loads this library via NetworkAgent::get_bambu_source_entry()
// (`dlopen` of `<data_dir>/plugins/libBambuSource.so`). We support both
// LAN video protocols:
//
//   * MJPG over TLS on port 6000 - used by A1 / A1 mini / P1 / P1P.
//     Protocol is the 80-byte auth packet + 16-byte frame headers
//     documented in OpenBambuAPI/video.md and implemented below.
//
//   * RTSPS on port 322 - used by X1 / P1S / P2S / N7. The RTSP/RTSPS
//     handshake plus RTP-H.264 depacketisation lives in
//     stubs/rtsp_client.cpp; stubs/rtsp_passthrough.cpp wraps that in
//     a worker thread that hands Annex-B-framed access units to the
//     C ABI. We do NOT decode or transcode: gstbambusrc.c (vendored
//     verbatim by both Bambu Studio and Orca Slicer on Linux) feeds
//     whatever Bambu_ReadSample returns into h264parse + avdec_h264 /
//     openh264dec / vaapih264dec, so the slicer-side pipeline does
//     all the heavy lifting and we stay free of any in-process
//     libavcodec dependency.
//
// URL formats we accept (all three appear in Studio's source):
//
//   bambu:///local/<ip>?port=6000&user=<u>&passwd=<p>&...
//   bambu:///local/<ip>.?port=6000&user=<u>&passwd=<p>&...        (legacy)
//       -> TCP/TLS MJPG on port 6000 (P1/A1 firmware protocol)
//
//   bambu:///rtsps___<user>:<passwd>@<ip>/streaming/live/1?proto=rtsps
//   bambu:///rtsp___<user>:<passwd>@<ip>/streaming/live/1?proto=rtsp
//       -> RTSP(S) on port 322 (X1/P1S/P2S/N7 firmware protocol);
//          routed through obn::rtsp::Passthrough (raw H.264 byte stream).
//
// Extra query parameters (device=, net_ver=, dev_ver=, cli_id=, ...) are
// ignored by the printer but device= is used for LAN TLS verify (SNI +
// CN=serial). The printer only cares about the auth packet (MJPG) or
// the RTSP DESCRIBE/SETUP/PLAY exchange.
//
// Protocol summary (see OpenBambuAPI/video.md for the canonical spec):
//
//   1. TLS handshake over TCP on <ip>:<port>; chain + CN=serial verified
//      via printer.cer unless OBN_SKIP_TLS_VERIFY is set.
//   2. Send 80-byte auth packet:
//        [0..3]   little-endian uint32 = 0x40          (payload size)
//        [4..7]   little-endian uint32 = 0x3000        (type: auth)
//        [8..11]  little-endian uint32 = 0             (flags)
//        [12..15] little-endian uint32 = 0
//        [16..47] 32 bytes: ASCII username, NUL-padded
//        [48..79] 32 bytes: ASCII password, NUL-padded
//   3. Server then streams frames indefinitely. Each frame is:
//        16-byte header (payload_size u32, itrack u32, flags u32, pad u32)
//        followed by `payload_size` bytes of JPEG data (FF D8 ... FF D9).
//
// gstbambusrc contract (see gstbambusrc.c):
//
//   Bambu_Create    (parse URL, allocate tunnel)
//   Bambu_SetLogger (attach log callback)
//   Bambu_Open      (blocking connect + TLS handshake + auth)
//   Bambu_StartStream(video=1) until it returns != would_block
//   Bambu_GetStreamCount / Bambu_GetStreamInfo   (once)
//   loop {
//     Bambu_ReadSample()      // would_block is fine, gst sleeps 33 ms
//     ...if success, emit buffer...
//   }
//   Bambu_Close + Bambu_Destroy at teardown.
//
// Thread safety: `gstbambusrc` calls us from a single streaming thread per
// tunnel; we only need to be safe against the logger callback being fired
// from that same thread. No global locks are held.

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "obn/os_compat.hpp"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "obn/json_lite.hpp"
#include "obn/lan_tls.hpp"
#include "obn/lan_tls_env.hpp"
#include "obn/tunnel_local.hpp"

#include "source_log.hpp"
#include "rtsp_passthrough.hpp"
#include "tls_socket.hpp"

#if defined(_WIN32)
#    define OBN_EXPORT extern "C" __declspec(dllexport)
#else
#    define OBN_EXPORT extern "C" __attribute__((visibility("default")))
#endif

// -----------------------------------------------------------------------
// Types redeclared from BambuTunnel.h. We do NOT include the original
// header because it is part of Bambu Studio's proprietary build tree
// (GPL-incompatible). All layout / enum values are checked against
// OpenBambuAPI documentation and gstbambusrc.c behaviour.
// -----------------------------------------------------------------------

extern "C" {

typedef void* Bambu_Tunnel;
// Studio's tchar contract differs by platform: Linux/macOS pass char*,
// Windows passes wchar_t* (matches wxMediaCtrl2's Bambu_FreeLogMsg /
// gstbambusrc's bambu_log signature).
#if defined(_WIN32)
using tchar = wchar_t;
#else
using tchar = char;
#endif

enum Bambu_StreamType { VIDE = 0, AUDI = 1 };
enum Bambu_VideoSubType { AVC1 = 0, MJPG = 1 };
enum Bambu_FormatType {
    video_avc_packet = 0,
    video_avc_byte_stream,
    video_jpeg,
    audio_raw,
    audio_adts,
};
enum Bambu_Error { Bambu_success = 0, Bambu_stream_end, Bambu_would_block, Bambu_buffer_limit };

struct Bambu_StreamInfo {
    int type;       // Bambu_StreamType
    int sub_type;   // Bambu_VideoSubType / Bambu_AudioSubType
    union {
        struct {
            int width;
            int height;
            int frame_rate;
        } video;
        struct {
            int sample_rate;
            int channel_count;
            int sample_size;
        } audio;
    } format;
    int                   format_type;    // Bambu_FormatType
    int                   format_size;
    int                   max_frame_size;
    unsigned char const*  format_buffer;
};

struct Bambu_Sample {
    int                   itrack;
    int                   size;
    int                   flags;
    unsigned char const*  buffer;
    unsigned long long    decode_time; // 100ns units, per gstbambusrc expectations
};

// Studio's Logger typedef. We keep the C-visible alias so the
// exported Bambu_SetLogger / Bambu_FreeLogMsg signatures stay
// byte-identical with what gstbambusrc and wxMediaCtrl2 expect.
using Logger = void (*)(void* context, int level, tchar const* msg);

} // extern "C"

// -----------------------------------------------------------------------
// All log/last-error helpers live in stubs/source_log.{hpp,cpp} so the
// RTSP client can share them. We pull the names into
// the anonymous namespace below so existing call sites (`log_fmt`,
// `log_at`, `mirror_log_fp`, `set_last_error`, `LL_DEBUG`, ...) keep
// compiling unchanged.
// -----------------------------------------------------------------------

namespace {

using obn::source::log_at;
using obn::source::log_fmt;
using obn::source::mirror_log_fp;
using obn::source::noop_logger;
using obn::source::set_last_error;
using obn::source::LL_TRACE;
using obn::source::LL_DEBUG;
using obn::source::LL_INFO;
using obn::source::LL_WARN;
using obn::source::LL_ERROR;
using obn::source::LL_OFF;

// -----------------------------------------------------------------------
// URL parser. Bambu URLs:
//   bambu:///local/<ip>?port=6000&user=<u>&passwd=<p>&...
//   bambu:///local/<ip>.?port=6000&...       (note the trailing dot)
// -----------------------------------------------------------------------

enum class Scheme {
    Local, // MJPG over TCP/TLS on <port> (default 6000)
    Rtsps, // RTSPS on <port> (default 322)
    Rtsp,  // plain RTSP on <port> (default 554)
};

struct TunnelUrl {
    Scheme      scheme = Scheme::Local;
    std::string host;
    int         port = 6000;
    std::string user = "bblp";
    std::string passwd;
    std::string device;
    std::string cli_id;
    std::string cli_ver;
    std::string net_ver;
    std::string path = "/streaming/live/1"; // RTSP(S) only
};

std::string url_decode(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return 10 + c - 'a';
                if (c >= 'A' && c <= 'F') return 10 + c - 'A';
                return -1;
            };
            int a = hex(s[i + 1]);
            int b = hex(s[i + 2]);
            if (a >= 0 && b >= 0) {
                out.push_back(static_cast<char>((a << 4) | b));
                i += 2;
                continue;
            }
        }
        out.push_back(s[i] == '+' ? ' ' : s[i]);
    }
    return out;
}

bool parse_url(const std::string& url, TunnelUrl* out)
{
    // Recognise the three URL shapes Studio hands us. Whichever it is,
    // strip the prefix and leave `rest` = "<...>[?query]".
    static const std::string p_local  = "bambu:///local/";
    static const std::string p_rtsps  = "bambu:///rtsps___";
    static const std::string p_rtsp   = "bambu:///rtsp___";

    std::string rest;
    if (url.compare(0, p_local.size(), p_local) == 0) {
        out->scheme = Scheme::Local;
        out->port   = 6000;
        rest = url.substr(p_local.size());
    } else if (url.compare(0, p_rtsps.size(), p_rtsps) == 0) {
        out->scheme = Scheme::Rtsps;
        out->port   = 322;
        rest = url.substr(p_rtsps.size());
    } else if (url.compare(0, p_rtsp.size(), p_rtsp) == 0) {
        out->scheme = Scheme::Rtsp;
        out->port   = 554;
        rest = url.substr(p_rtsp.size());
    } else {
        // Bare "<ip>:<port>/..." fallback.
        out->scheme = Scheme::Local;
        out->port   = 6000;
        rest = url;
    }

    // Split host.part vs ?query.
    auto q_pos = rest.find('?');
    std::string host_part = (q_pos == std::string::npos) ? rest : rest.substr(0, q_pos);
    std::string query     = (q_pos == std::string::npos) ? ""   : rest.substr(q_pos + 1);

    if (out->scheme == Scheme::Rtsps || out->scheme == Scheme::Rtsp) {
        // "<user>:<passwd>@<host>[:port]/<path>" (path is required and
        // Studio always sends "streaming/live/1").
        auto at_pos = host_part.find('@');
        if (at_pos != std::string::npos) {
            std::string userinfo = host_part.substr(0, at_pos);
            host_part            = host_part.substr(at_pos + 1);
            auto col             = userinfo.find(':');
            if (col != std::string::npos) {
                out->user   = url_decode(userinfo.substr(0, col));
                out->passwd = url_decode(userinfo.substr(col + 1));
            } else {
                out->user = url_decode(userinfo);
            }
        }
        auto slash = host_part.find('/');
        if (slash != std::string::npos) {
            out->path = host_part.substr(slash); // includes leading '/'
            host_part = host_part.substr(0, slash);
        }
        // Host may still carry ":<port>". Fall through to the colon
        // handling below.
    } else {
        // Legacy MJPG URL: "<ip>.?port=..." -> trim trailing . and /
        while (!host_part.empty() &&
               (host_part.back() == '/' || host_part.back() == '.'))
            host_part.pop_back();
    }

    // Optional ":<port>" in host_part.
    auto colon = host_part.find(':');
    if (colon != std::string::npos) {
        out->host = host_part.substr(0, colon);
        try {
            out->port = std::stoi(host_part.substr(colon + 1));
        } catch (...) {
            return false;
        }
    } else {
        out->host = host_part;
    }

    // Parse query. Local-scheme URLs carry user/passwd here;
    // RTSP(S) URLs carry them in the userinfo above, so these are
    // effectively a no-op for those.
    size_t i = 0;
    while (i < query.size()) {
        auto amp = query.find('&', i);
        if (amp == std::string::npos) amp = query.size();
        auto kv = query.substr(i, amp - i);
        auto eq = kv.find('=');
        std::string key = (eq == std::string::npos) ? kv : kv.substr(0, eq);
        std::string val = (eq == std::string::npos) ? "" : url_decode(kv.substr(eq + 1));
        if      (key == "port")   { try { out->port = std::stoi(val); } catch (...) { /* keep default */ } }
        else if (key == "user")   { out->user = val; }
        else if (key == "passwd") { out->passwd = val; }
        else if (key == "device") { out->device = val; }
        else if (key == "cli_id") { out->cli_id = val; }
        else if (key == "cli_ver") { out->cli_ver = val; }
        else if (key == "net_ver") { out->net_ver = val; }
        i = amp + 1;
    }

    return !out->host.empty() && out->port > 0;
}

// -----------------------------------------------------------------------
// OpenSSL one-time init via tls_socket (shared with RTSPS / FTPS paths).
// -----------------------------------------------------------------------

void ssl_init_once()
{
    // Ensures OpenSSL + the shared tls_socket SSL_CTX are ready.
    (void)obn::tls::shared_ctx();
}

// -----------------------------------------------------------------------
// Tunnel state. All network IO is synchronous (blocking) on purpose;
// gstbambusrc already runs us on a dedicated streaming thread.
// -----------------------------------------------------------------------

// Reasonable upper bound for a single 1280x720 JPEG frame. The stock
// camera tops out around 60 KB but we give ourselves a whole megabyte
// of headroom in case Bambu ships higher-res firmware later.
constexpr size_t kMaxFrameSize = 1u << 20;

// --------------------------------------------------------------------
// PrinterFileSystem CTRL state.
//
// Studio opens a port-6000 tunnel through us (Bambu_Create/Bambu_Open
// on `bambu:///local/<ip>.?port=6000&user=bblp&passwd=<code>&...`) and
// then calls `Bambu_StartStreamEx(tunnel, CTRL_TYPE=0x3001)`. After
// that point it stops asking for video and instead pushes JSON request
// strings through `Bambu_SendMessage(CTRL_TYPE)`, expecting JSON
// responses through `Bambu_ReadSample`. We forward those frames to
// printer firmware over the same TLS :6000 session (native passthrough).
// --------------------------------------------------------------------

constexpr int kCtrlType    = 0x3001;
constexpr int kResContinue = 1;

struct CtrlRequest {
    int         cmdtype = 0;
    int         sequence = 0;
    std::string body; // full JSON text, including "{...}\n\n<blob>" if present
};

struct CtrlReply {
    // "<json>\n\n<optional blob>" in PrinterFileSystem wire format.
    std::string data;
};

struct Tunnel {
    TunnelUrl        url;
    Logger           logger  = noop_logger;
    void*            log_ctx = nullptr;

    // ---- MJPG/TLS state (Scheme::Local) ----
    obn::os::socket_t fd     = obn::os::kInvalidSocket;
    SSL*             ssl     = nullptr;

    // ---- RTSP(S) state (Scheme::Rtsps/Rtsp) ----
    // Custom RTSP/RTSPS client wrapped by an Annex-B passthrough
    // worker (rtsp_passthrough.hpp). Built lazily by open_rtsp();
    // destroyed by tunnel_close(). Hands raw H.264 byte-stream
    // straight to gstbambusrc, which decodes via h264parse +
    // avdec_h264/openh264dec on the slicer side -- no in-process
    // libavcodec is required (Bambu Studio's bundled libavcodec is
    // decoder-only, and Orca Slicer doesn't ship one at all).
    std::unique_ptr<obn::rtsp::Passthrough> rtsp_pass;

    // Subtype of the video carried by this tunnel, filled in by
    // Bambu_GetStreamInfo. MJPG for local-scheme tunnels (port 6000,
    // A1/P1/A1 mini), AVC1 for RTSP(S) tunnels (X1/P1S/P2S/N7).
    int              sub_type = MJPG;

    // Bookkeeping for GetStreamInfo. We don't know the real frame rate
    // until we've observed several frames, so these are "advisory" and
    // Studio uses them only for display.
    int              width      = 1280;
    int              height     = 720;
    int              frame_rate = 15;

    // Reused across ReadSample calls so the Bambu_Sample::buffer pointer
    // stays valid until the NEXT ReadSample is invoked (matches what
    // gstbambusrc does with `g_memdup(sample.buffer, sample.size)`).
    std::vector<uint8_t> frame_buf;

    // Monotonic "decode_time" in the 100-ns units gstbambusrc feeds to
    // gstreamer. We derive it from a steady_clock zeroed at Open() time.
    std::chrono::steady_clock::time_point t0{};
    bool                                  started = false;

    // Cancellation flag set from a different thread by Bambu_Close.
    std::atomic<bool> closing{false};

    // Serialises access to `ssl` / `fd` against tunnel_close. Held by
    // every SSL_read iteration on the streaming thread, and acquired
    // by tunnel_close after it has shut the socket down (which wakes
    // any blocked SSL_read so the lock can actually be obtained).
    // Without this Studio's reconnect-on-stall path used to free SSL
    // out from under the reader and segfault.
    std::mutex mjpg_io_mu;

    // Diagnostic counter; we log a line every Nth frame so the mirror
    // file tells us "stream is alive" without drowning in per-frame spam.
    std::uint64_t frame_count = 0;

    // Local MJPEG auth is deferred until Bambu_StartStream (file browser
    // uses Bambu_StartStreamEx without the 80-byte 0x3000 auth packet).
    bool mjpg_authed = false;

    // ---- PrinterFileSystem CTRL state (Scheme::Local + CTRL_TYPE) ----
    // When Studio calls Bambu_StartStreamEx(CTRL_TYPE), we keep the TLS
    // :6000 socket open and forward CTRL JSON to printer firmware.
    bool             ctrl_mode = false;

    std::unique_ptr<obn::tunnel_local::Session> tl_session;

    // CTRL request inbox (Bambu_SendMessage) and reply outbox
    // (Bambu_ReadSample). Both guarded by ctrl_mu.
    std::mutex                 ctrl_mu;
    std::condition_variable    ctrl_cv;
    std::deque<CtrlRequest>    ctrl_in;
    std::deque<CtrlReply>      ctrl_out;
    std::atomic<bool>          ctrl_stop{false};
    std::thread                ctrl_worker;

    // Scratch storage for the CtrlReply currently exposed via
    // Bambu_ReadSample's `sample->buffer`. We keep it alive until the
    // NEXT ReadSample call (same contract as frame_buf above).
    std::string                ctrl_current_reply;
};

void tunnel_close(Tunnel* t)
{
    if (!t) return;
    t->closing.store(true, std::memory_order_release);
    log_at(LL_DEBUG, t->logger, t->log_ctx,
           "tunnel_close: shutting down (fd=%lld ssl=%p frames=%llu)",
           static_cast<long long>(t->fd), static_cast<void*>(t->ssl),
           static_cast<unsigned long long>(t->frame_count));

    // Step 1 (no lock): wake the reader. SSL_read on the streaming
    // thread sits in recv() up to SO_RCVTIMEO (5 s); shutting down
    // the socket from under it makes recv() return immediately so it
    // can drop mjpg_io_mu and let us free the SSL object below. This
    // is intentionally done WITHOUT mjpg_io_mu -- we'd deadlock against
    // the in-flight SSL_read otherwise.
    if (obn::os::socket_valid(t->fd)) obn::os::shutdown_both(t->fd);

    // Step 2: serialise with the reader. Once we hold mjpg_io_mu nobody
    // can be inside SSL_read on this tunnel, so SSL_free is safe.
    {
        std::lock_guard<std::mutex> lk(t->mjpg_io_mu);
        if (t->ssl) {
            // Best-effort close_notify; the printer doesn't care and
            // the socket is already half-shut so SSL_shutdown will
            // return quickly even if the write fails.
            SSL_shutdown(t->ssl);
            SSL_free(t->ssl);
            t->ssl = nullptr;
        }
        if (obn::os::socket_valid(t->fd)) {
            obn::os::close_socket(t->fd);
            t->fd = obn::os::kInvalidSocket;
        }
    }

    if (t->rtsp_pass) {
        // stop() joins the worker thread and tears the RTSP client
        // down. Reset the unique_ptr afterwards so a half-destroyed
        // passthrough cannot be reached again on a Bambu_Open retry.
        t->rtsp_pass->stop();
        t->rtsp_pass.reset();
    }
}

// Reads exactly `len` bytes. Returns 0 on OK, 1 on EOF, -1 on error.
//
// The SSL object and SSL_get_error access are taken under
// `t->mjpg_io_mu` so a concurrent tunnel_close() cannot pull SSL out
// from under us. tunnel_close() shuts the socket down first, which
// causes the in-flight SSL_read to return promptly with an error so
// we drop the lock and let the closer make progress.
int ssl_read_all(Tunnel* t, void* buf, size_t len)
{
    auto* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < len) {
        if (t->closing.load(std::memory_order_acquire)) return -1;
        int n;
        int err = SSL_ERROR_NONE;
        {
            std::lock_guard<std::mutex> lk(t->mjpg_io_mu);
            if (!t->ssl || t->closing.load(std::memory_order_acquire))
                return -1;
            n = SSL_read(t->ssl, p + got, static_cast<int>(len - got));
            if (n <= 0) err = SSL_get_error(t->ssl, n);
        }
        if (n <= 0) {
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            if (err == SSL_ERROR_ZERO_RETURN) {
                log_at(LL_DEBUG, t->logger, t->log_ctx,
                       "ssl_read_all: clean EOF after %zu/%zu bytes",
                       got, len);
                return 1;
            }
            log_at(LL_DEBUG, t->logger, t->log_ctx,
                   "ssl_read_all: SSL_read failed n=%d err=%d errno=%d "
                   "after %zu/%zu bytes",
                   n, err, errno, got, len);
            return -1;
        }
        got += static_cast<size_t>(n);
    }
    return 0;
}

// -----------------------------------------------------------------------
// RTSP(S) video. We do not transcode: the printer sends H.264 over
// RTP and gstbambusrc.c (vendored verbatim by both Bambu Studio and
// Orca Slicer on Linux) feeds whatever Bambu_ReadSample returns into
// `h264parse ! avdec_h264 / openh264dec / vaapih264dec`. So this side
// only has to do RTSP/RTSPS handshake + RTP depacketisation + Annex-B
// framing. All of that lives in stubs/rtsp_client.cpp and
// stubs/rtsp_passthrough.cpp; here we just glue them onto the C ABI.
// -----------------------------------------------------------------------

[[maybe_unused]] int open_rtsp(Tunnel* t)
{
    auto pass = std::make_unique<obn::rtsp::Passthrough>(t->logger, t->log_ctx);

    log_fmt(t->logger, t->log_ctx,
            "open_rtsp: dialing %s://%s:%d (user=%s)",
            t->url.scheme == Scheme::Rtsps ? "rtsps" : "rtsp",
            t->url.host.c_str(), t->url.port, t->url.user.c_str());

    if (pass->start(t->url.host, t->url.port, t->url.user, t->url.passwd,
                    t->url.path, t->url.scheme == Scheme::Rtsps,
                    t->url.device) != 0) {
        return -1;
    }

    t->rtsp_pass = std::move(pass);
    // gstbambusrc looks at sub_type via Bambu_GetStreamInfo; AVC1 +
    // video_avc_byte_stream is the format gstbambusrc's downstream
    // pipeline already speaks (h264parse copes with any framing
    // h264parse can detect, and Annex-B is the simplest one).
    t->sub_type   = AVC1;
    // Width/height/frame_rate are advisory until h264parse pulls them
    // out of SPS; surface the firmware's well-known 1280x720@30 default
    // so Studio's UI shows reasonable numbers from the start.
    t->width      = 1280;
    t->height     = 720;
    t->frame_rate = 30;
    t->t0         = std::chrono::steady_clock::now();
    t->started    = true;
    log_fmt(t->logger, t->log_ctx,
            "open_rtsp: passthrough ready (avc1 %dx%d, gstbambusrc decodes)",
            t->width, t->height);
    return Bambu_success;
}

int read_rtsp(Tunnel* t, Bambu_Sample* sample)
{
    if (!t->rtsp_pass) return -1;
    const std::uint8_t* buf      = nullptr;
    std::size_t         size     = 0;
    std::uint64_t       dt_100ns = 0;
    int                 flags    = 0;
    auto rc = t->rtsp_pass->try_pull(&buf, &size, &dt_100ns, &flags);
    switch (rc) {
        case obn::rtsp::Passthrough::Pull_Ok:
            break;
        case obn::rtsp::Passthrough::Pull_WouldBlock:
            return Bambu_would_block;
        case obn::rtsp::Passthrough::Pull_StreamEnd:
            return Bambu_stream_end;
        case obn::rtsp::Passthrough::Pull_Error:
        default:
            return -1;
    }

    sample->itrack      = 0;
    sample->size        = static_cast<int>(size);
    sample->flags       = flags;
    sample->buffer      = buf;
    sample->decode_time = static_cast<unsigned long long>(dt_100ns);
    return Bambu_success;
}


// -----------------------------------------------------------------------
// Build the 80-byte auth packet per OpenBambuAPI/video.md.
// -----------------------------------------------------------------------
void build_auth_packet(const TunnelUrl& url, uint8_t out[80])
{
    std::memset(out, 0, 80);
    auto put_u32_le = [&](size_t off, uint32_t v) {
        out[off + 0] = static_cast<uint8_t>( v        & 0xff);
        out[off + 1] = static_cast<uint8_t>((v >> 8)  & 0xff);
        out[off + 2] = static_cast<uint8_t>((v >> 16) & 0xff);
        out[off + 3] = static_cast<uint8_t>((v >> 24) & 0xff);
    };
    put_u32_le(0,  0x40);       // payload size (always 0x40 for auth)
    put_u32_le(4,  0x3000);     // packet type (auth)
    put_u32_le(8,  0);          // flags
    put_u32_le(12, 0);
    // Username / password into 32-byte fixed-size fields, NUL-padded.
    std::memcpy(out + 16, url.user.data(),
                std::min<size_t>(url.user.size(), 32));
    std::memcpy(out + 48, url.passwd.data(),
                std::min<size_t>(url.passwd.size(), 32));
}

void push_reply(Tunnel* t, CtrlReply r)
{
    std::lock_guard<std::mutex> lk(t->ctrl_mu);
    t->ctrl_out.emplace_back(std::move(r));
    t->ctrl_cv.notify_all();
}

bool parse_ctrl_request(const std::string& wire, int* cmdtype, int* sequence,
                        obn::json::Value* req)
{
    std::size_t j_end = wire.find("\n\n");
    std::string j = (j_end == std::string::npos) ? wire : wire.substr(0, j_end);
    std::string perr;
    auto v = obn::json::parse(j, &perr);
    if (!v) return false;
    auto ct = v->find("cmdtype");
    auto sq = v->find("sequence");
    if (!ct.is_number() || !sq.is_number()) return false;
    *cmdtype  = static_cast<int>(ct.as_number());
    *sequence = static_cast<int>(sq.as_number());
    *req      = v->find("req");
    return true;
}

static int parse_wire_result(const std::string& wire)
{
    const std::size_t j_end = wire.find("\n\n");
    const std::string j =
        (j_end == std::string::npos) ? wire : wire.substr(0, j_end);
    std::string perr;
    const auto v = obn::json::parse(j, &perr);
    if (!v) return -1;
    return static_cast<int>(v->find("result").as_int(-1));
}

static void native_ctrl_send_worker(Tunnel* t)
{
    log_fmt(t->logger, t->log_ctx, "ctrl: native send worker started");
    while (!t->ctrl_stop.load(std::memory_order_acquire)) {
        CtrlRequest req;
        {
            std::unique_lock<std::mutex> lk(t->ctrl_mu);
            t->ctrl_cv.wait_for(lk, std::chrono::milliseconds(200), [&] {
                return t->ctrl_stop.load(std::memory_order_acquire) ||
                       !t->ctrl_in.empty();
            });
            if (t->ctrl_stop.load(std::memory_order_acquire)) break;
            if (t->ctrl_in.empty()) continue;
            req = std::move(t->ctrl_in.front());
            t->ctrl_in.pop_front();
        }
        if (!t->ssl || !t->tl_session) continue;
        int cmdtype = 0, sequence = 0;
        obn::json::Value body;
        if (parse_ctrl_request(req.body, &cmdtype, &sequence, &body)) {
            log_fmt(t->logger, t->log_ctx,
                    "ctrl: native forward cmd=0x%04x seq=%d (%zu bytes)",
                    cmdtype, sequence, req.body.size());
        } else {
            log_fmt(t->logger, t->log_ctx,
                    "ctrl: native forward %zu bytes (unparsed)", req.body.size());
        }
        if (t->tl_session->send_abi_json(t->ssl, req.body, &t->mjpg_io_mu) != 0) {
            log_fmt(t->logger, t->log_ctx, "ctrl: native send failed");
            set_last_error("BambuTunnelLocal send failed");
            continue;
        }
        for (;;) {
            std::vector<std::uint8_t> wire;
            if (t->tl_session->recv_payload(t->ssl, &wire, &t->mjpg_io_mu) != 0) {
                log_fmt(t->logger, t->log_ctx, "ctrl: native recv failed");
                set_last_error("BambuTunnelLocal recv failed");
                break;
            }
            CtrlReply reply;
            reply.data.assign(reinterpret_cast<const char*>(wire.data()),
                              wire.size());
            log_fmt(t->logger, t->log_ctx,
                    "ctrl: native recv %zu bytes", reply.data.size());
            const int result = parse_wire_result(reply.data);
            push_reply(t, std::move(reply));
            if (result != kResContinue) break;
        }
    }
    log_fmt(t->logger, t->log_ctx, "ctrl: native send worker exited");
}

static int start_native_ctrl_handshake(Tunnel* t)
{
    if (!t->ssl) {
        set_last_error("CTRL: TLS session not open");
        return -1;
    }
    // StartStreamEx is polled (Bambu_would_block between steps). Keep one
    // Session across polls — recreating it here re-sent login on every tick.
    if (!t->tl_session) {
        t->tl_session = std::make_unique<obn::tunnel_local::Session>(
            static_cast<std::uint32_t>(std::rand()));
    }
    obn::tunnel_local::Config cfg;
    cfg.username    = t->url.user;
    cfg.access_code = t->url.passwd;
    cfg.client_id   = t->url.cli_id;
    if (!t->url.cli_ver.empty()) {
        cfg.client_ver = t->url.cli_ver;
    } else if (!t->url.net_ver.empty()) {
        cfg.client_ver = t->url.net_ver;
    }

    const int hs = t->tl_session->handshake_step(t->ssl, cfg, &t->mjpg_io_mu);
    if (hs < 0) {
        const auto ph = t->tl_session->phase();
        log_fmt(t->logger, t->log_ctx,
                "ctrl: native handshake failed (phase=%d)",
                static_cast<int>(ph));
        t->tl_session.reset();
        set_last_error("BambuTunnelLocal handshake failed");
        return -1;
    }
    if (hs > 0) return Bambu_would_block;

    if (!t->ctrl_mode) {
        t->ctrl_mode        = true;
        t->ctrl_stop.store(false, std::memory_order_release);
        t->ctrl_worker      = std::thread(native_ctrl_send_worker, t);
        log_fmt(t->logger, t->log_ctx,
                "ctrl: native :6000 passthrough ready (pid=%s ver=%s)",
                cfg.client_id.c_str(), cfg.client_ver.c_str());
    }
    return Bambu_success;
}

// Shuts the worker down. Idempotent.
void stop_ctrl_mode(Tunnel* t)
{
    if (!t->ctrl_mode) return;
    {
        std::lock_guard<std::mutex> lk(t->ctrl_mu);
        t->ctrl_stop.store(true, std::memory_order_release);
        t->ctrl_cv.notify_all();
    }
    if (t->ctrl_worker.joinable()) t->ctrl_worker.join();
    t->tl_session.reset();
    t->ctrl_mode = false;
}

} // namespace

// =======================================================================
// Exported BambuLib API
// =======================================================================

OBN_EXPORT int Bambu_Init()
{
    ssl_init_once();
    return Bambu_success;
}

OBN_EXPORT void Bambu_Deinit()
{
    // No-op: we intentionally leak the global SSL_CTX until process exit.
    // Tearing it down while other tunnels might still be alive on a
    // different GstElement is not worth the race risk.
}

OBN_EXPORT int Bambu_Create(Bambu_Tunnel* tunnel, char const* path)
{
    if (!tunnel || !path) return -1;
    ssl_init_once();
    auto* t = new Tunnel();
    // Hide the password from the mirror log but keep the host/port/user
    // portion so we know what the caller actually asked for.
    log_fmt(t->logger, t->log_ctx, "Bambu_Create: url=%.160s%s", path,
            std::strlen(path) > 160 ? "..." : "");
    if (!parse_url(path, &t->url)) {
        log_fmt(t->logger, t->log_ctx, "Bambu_Create: bad URL");
        delete t;
        set_last_error("bad URL");
        return -1;
    }
    const char* scheme_name = (t->url.scheme == Scheme::Rtsps) ? "rtsps"
                            : (t->url.scheme == Scheme::Rtsp)  ? "rtsp"
                            :                                    "local";
    log_fmt(t->logger, t->log_ctx,
            "Bambu_Create: parsed scheme=%s host=%s port=%d path=%s "
            "user=%s passwd=%s",
            scheme_name, t->url.host.c_str(), t->url.port,
            t->url.path.c_str(), t->url.user.c_str(),
            t->url.passwd.empty() ? "(empty!)" : "***");
    if (!t->url.device.empty() && !t->url.host.empty()) {
        obn::lan_tls::registry_put_ip_serial(t->url.host, t->url.device);
    }
    *tunnel = t;
    return Bambu_success;
}

OBN_EXPORT void Bambu_SetLogger(Bambu_Tunnel tunnel, Logger logger, void* context)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return;
    t->logger  = logger ? logger : noop_logger;
    t->log_ctx = context;
}

OBN_EXPORT int Bambu_Open(Bambu_Tunnel tunnel)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return -1;

    // RTSP(S) is so different from MJPG that it gets its own code path
    // (passthrough worker + RTSP handshake); MJPG stays as manual
    // TLS + auth packet below. Both the stock plugin and our passthrough
    // hand raw H.264 byte-stream back to gstbambusrc, so this path is
    // gated only on the URL scheme.
    if (t->url.scheme == Scheme::Rtsps || t->url.scheme == Scheme::Rtsp) {
        return open_rtsp(t);
    }

    log_fmt(t->logger, t->log_ctx, "Bambu_Open: dialing tls://%s:%d",
            t->url.host.c_str(), t->url.port);

    const char* serial =
        t->url.device.empty() ? nullptr : t->url.device.c_str();
    if (obn::tls::dial_tls(t->url.host, t->url.port, /*timeout_ms=*/5000,
                           &t->fd, &t->ssl, serial) != 0) {
        log_fmt(t->logger, t->log_ctx, "Bambu_Open: TLS dial failed: %s",
                obn::source::get_last_error());
        return -1;
    }

    log_fmt(t->logger, t->log_ctx,
            "Bambu_Open: TLS established (cipher=%s)",
            SSL_get_cipher(t->ssl));

    t->t0      = std::chrono::steady_clock::now();
    t->started = true;
    log_fmt(t->logger, t->log_ctx,
            "Bambu_Open: TLS ready (MJPEG auth deferred to StartStream)");
    return Bambu_success;
}

OBN_EXPORT int Bambu_StartStream(Bambu_Tunnel tunnel, bool /*video*/)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return -1;
    if (t->url.scheme == Scheme::Local && !t->ssl) return -1;
    if ((t->url.scheme == Scheme::Rtsps ||
         t->url.scheme == Scheme::Rtsp) && !t->rtsp_pass) return -1;

    if (t->url.scheme == Scheme::Local && !t->ctrl_mode && !t->mjpg_authed) {
        uint8_t auth[80];
        build_auth_packet(t->url, auth);
        std::lock_guard<std::mutex> lk(t->mjpg_io_mu);
        if (obn::tls::ssl_write_all(t->ssl, auth, sizeof(auth)) != 0) {
            set_last_error("MJPEG auth write failed");
            return -1;
        }
        t->mjpg_authed = true;
        log_fmt(t->logger, t->log_ctx,
                "Bambu_StartStream: sent %zu-byte MJPEG auth", sizeof(auth));
    }
    return Bambu_success;
}

OBN_EXPORT int Bambu_StartStreamEx(Bambu_Tunnel tunnel, int type)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return -1;
    // CTRL_TYPE (0x3001) opens the PrinterFileSystem channel: keep TLS
    // :6000 open and forward CTRL JSON to printer firmware.
    if (type == kCtrlType) {
        return start_native_ctrl_handshake(t);
    }
    return Bambu_StartStream(tunnel, true);
}

OBN_EXPORT int Bambu_GetStreamCount(Bambu_Tunnel tunnel)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return 0;
    if (t->url.scheme == Scheme::Local && !t->ssl)      return 0;
    if ((t->url.scheme == Scheme::Rtsps ||
         t->url.scheme == Scheme::Rtsp) && !t->rtsp_pass) return 0;
    return 1; // one video track (MJPEG for local-scheme, AVC1 for RTSP).
}

OBN_EXPORT int Bambu_GetStreamInfo(Bambu_Tunnel tunnel, int index,
                                   Bambu_StreamInfo* info)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t || !info || index != 0) return -1;
    std::memset(info, 0, sizeof(*info));
    info->type                    = VIDE;
    info->sub_type                = t->sub_type;
    info->format.video.width      = t->width;
    info->format.video.height     = t->height;
    info->format.video.frame_rate = t->frame_rate;
    // For H.264, gstbambusrc feeds the buffer into a decoder bin which
    // sniffs the byte stream; video_avc_byte_stream mirrors what the
    // proprietary plugin advertises in RTSP mode.
    info->format_type             = (t->sub_type == MJPG)
                                        ? video_jpeg
                                        : video_avc_byte_stream;
    info->format_size             = 0;
    info->max_frame_size          = static_cast<int>(kMaxFrameSize);
    info->format_buffer           = nullptr;
    return Bambu_success;
}

OBN_EXPORT unsigned long Bambu_GetDuration(Bambu_Tunnel /*tunnel*/)
{
    return 0; // live stream, no duration
}

OBN_EXPORT int Bambu_Seek(Bambu_Tunnel /*tunnel*/, unsigned long /*time*/)
{
    return Bambu_success; // meaningless for a live stream
}

OBN_EXPORT int Bambu_ReadSample(Bambu_Tunnel tunnel, Bambu_Sample* sample)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t || !sample) return -1;

    // CTRL channel: drain one reply from the outbox. PrinterFileSystem
    // on Studio's side will loop calling us until would_block or until
    // it sees the terminal reply it's waiting on.
    if (t->ctrl_mode) {
        std::unique_lock<std::mutex> lk(t->ctrl_mu);
        if (t->ctrl_out.empty()) return Bambu_would_block;
        CtrlReply r = std::move(t->ctrl_out.front());
        t->ctrl_out.pop_front();
        lk.unlock();
        // Stash on the tunnel so the pointer stays valid until next
        // ReadSample (matches the contract with gstbambusrc). PrinterFileSystem
        // treats decode_time as irrelevant; we set it to 0.
        t->ctrl_current_reply = std::move(r.data);
        sample->itrack      = 0;
        sample->size        = static_cast<int>(t->ctrl_current_reply.size());
        sample->flags       = 0;
        sample->buffer      = reinterpret_cast<const unsigned char*>(
                                   t->ctrl_current_reply.data());
        sample->decode_time = 0;
        return Bambu_success;
    }

    // RTSP: pull from the IVideoPipeline. MJPG path continues below.
    if (t->url.scheme == Scheme::Rtsps || t->url.scheme == Scheme::Rtsp) {
        return read_rtsp(t, sample);
    }

    if (!t->ssl) return -1;

    // Read 16-byte frame header.
    uint8_t hdr[16];
    int rc = ssl_read_all(t, hdr, sizeof(hdr));
    if (rc < 0) {
        set_last_error("header read failed");
        return -1;
    }
    if (rc > 0) return Bambu_stream_end;

    auto u32 = [&](size_t off) -> uint32_t {
        return  (static_cast<uint32_t>(hdr[off + 0]))
              | (static_cast<uint32_t>(hdr[off + 1]) << 8)
              | (static_cast<uint32_t>(hdr[off + 2]) << 16)
              | (static_cast<uint32_t>(hdr[off + 3]) << 24);
    };
    uint32_t payload_size = u32(0);
    uint32_t itrack       = u32(4);
    uint32_t flags        = u32(8);

    if (payload_size == 0 || payload_size > kMaxFrameSize) {
        log_fmt(t->logger, t->log_ctx,
                "Bambu_ReadSample: bogus payload size %u", payload_size);
        set_last_error("bogus payload size");
        return -1;
    }

    t->frame_buf.resize(payload_size);
    rc = ssl_read_all(t, t->frame_buf.data(), payload_size);
    if (rc < 0) {
        set_last_error("payload read failed");
        return -1;
    }
    if (rc > 0) return Bambu_stream_end;

    // Sanity check: MJPG frames start with 0xFF 0xD8 and end with
    // 0xFF 0xD9. If the magic is wrong we probably lost sync; bailing
    // out lets gstbambusrc tear the pipeline down and reconnect.
    if (payload_size < 4 ||
        t->frame_buf[0] != 0xFF || t->frame_buf[1] != 0xD8 ||
        t->frame_buf[payload_size - 2] != 0xFF ||
        t->frame_buf[payload_size - 1] != 0xD9) {
        log_fmt(t->logger, t->log_ctx,
                "Bambu_ReadSample: JPEG magic mismatch size=%u", payload_size);
        set_last_error("JPEG magic mismatch");
        return -1;
    }

    auto now = std::chrono::steady_clock::now();
    auto ns  = std::chrono::duration_cast<std::chrono::nanoseconds>(now - t->t0).count();

    if (++t->frame_count == 1 || (t->frame_count % 60) == 0) {
        log_fmt(t->logger, t->log_ctx,
                "Bambu_ReadSample: frame #%llu size=%u itrack=%u flags=%u",
                static_cast<unsigned long long>(t->frame_count),
                payload_size, itrack, flags);
    }

    sample->itrack      = static_cast<int>(itrack);
    sample->size        = static_cast<int>(payload_size);
    sample->flags       = static_cast<int>(flags);
    sample->buffer      = t->frame_buf.data();
    // gstbambusrc multiplies decode_time by 100 to get ns, so we divide.
    sample->decode_time = static_cast<unsigned long long>(ns / 100);
    return Bambu_success;
}

OBN_EXPORT int Bambu_SendMessage(Bambu_Tunnel tunnel, int ctrl,
                                 char const* data, int len)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t || !data || len <= 0) return -1;
    // Only CTRL_TYPE is known to us. Any other ctrl channel is a
    // no-op (returns success so the caller doesn't interpret it as
    // pipe-dead); stock firmware uses the same channel number.
    if (ctrl != kCtrlType) return Bambu_success;
    if (!t->ctrl_mode) {
        set_last_error("CTRL channel not ready");
        return -1;
    }
    CtrlRequest req;
    req.body.assign(data, static_cast<std::size_t>(len));
    {
        std::lock_guard<std::mutex> lk(t->ctrl_mu);
        t->ctrl_in.emplace_back(std::move(req));
        t->ctrl_cv.notify_all();
    }
    return Bambu_success;
}

OBN_EXPORT int Bambu_RecvMessage(Bambu_Tunnel /*tunnel*/, int* /*ctrl*/,
                                 char* /*data*/, int* /*len*/)
{
    // Studio uses Bambu_ReadSample for CTRL replies, not RecvMessage.
    // Keep this as a polite "no data".
    return Bambu_would_block;
}

OBN_EXPORT void Bambu_Close(Bambu_Tunnel tunnel)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return;
    // CTRL worker must be joined before the rest of the tunnel is
    // dismantled (it holds references to SSL that tunnel_close would
    // would invalidate).
    stop_ctrl_mode(t);
    tunnel_close(t);
}

OBN_EXPORT void Bambu_Destroy(Bambu_Tunnel tunnel)
{
    auto* t = static_cast<Tunnel*>(tunnel);
    if (!t) return;
    stop_ctrl_mode(t);
    tunnel_close(t);
    delete t;
}

OBN_EXPORT char const* Bambu_GetLastErrorMsg()
{
    // Stock plugin returns a static string; we return a thread-local
    // pointer that remains valid until the next set_last_error on
    // the same thread. That matches how Studio actually uses it
    // (printed immediately, not stored).
    return obn::source::get_last_error();
}

OBN_EXPORT void Bambu_FreeLogMsg(tchar const* msg)
{
    // We allocated with strdup_for_logger() in log_fmt(): strdup() on
    // POSIX, malloc(wcslen+1) on Windows. Both come back to free().
    if (msg) std::free(const_cast<tchar*>(msg));
}

// Legacy probe: the older stub exported this so callers could tell at a
// glance that they loaded our build. Keep it around (no-op).
OBN_EXPORT int bambu_source_is_stub()
{
    return 0; // now a real implementation
}
