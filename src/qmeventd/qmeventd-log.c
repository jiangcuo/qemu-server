// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    qmeventd key-event journal logging.

    One record per line, always on a single physical line so journald sees an
    individual message. The payload is compact json-c output, which escapes
    quotes, newlines and control characters, so guest supplied strings cannot
    forge additional journal records. In addition the vmid/source/event tokens
    are validated here: a value outside the expected token shape is rendered as
    "-" and its raw text is preserved inside the JSON payload for diagnostics,
    never interpolated into the line structure.

    Record layout (fields in this exact order, no exceptions):

      vmid=<VMID|-> qemu_pid=<PID|-> peer_pid=<PID|-> level=<info|warning|error>
      source=<qmp|qmeventd|vzdump> event=<NAME> payload=<single-line JSON>

    A *bare severity* prefix is prepended so that the unit's
    SyslogLevelPrefix=yes maps INFO/ WARNING/ ERROR to the journal PRIORITY:
    <6> = info, <4> = warning, <3> = error. A facility-encoded value such as
    <14> is not understood by systemd's standard-stream parser: it is kept
    verbatim in MESSAGE and the PRIORITY silently stays at the default, so the
    facility bits must NOT be added here.

    Delivery is best effort and must never block the control loop. The sink is
    the daemon's standard output, which systemd always backs with an AF_UNIX
    socket; that is the only sink this layer supports. send(MSG_DONTWAIT |
    MSG_NOSIGNAL) is used, so a partial write stays in a bounded buffer and a
    dead peer raises no SIGPIPE. Any other fd (pipe, tty, regular file) is
    explicitly rejected: writing it non-blockingly is impossible without
    touching shared fd state (fcntl on stdout would also affect QMP and the
    forked children), and a raw write() would raise SIGPIPE or block. Records
    for an unsupported sink are accounted as dropped instead.

    Accounting is explicit: `accepted` counts records admitted into the
    pipeline, `delivered` counts records fully written to the sink, and
    `dropped_lines`/`dropped_bytes` count records (and bytes) that will never
    be delivered, whether they were admitted and then discarded or rejected
    outright (unsupported sink, full buffer, per-owner quota). Because a
    rejected attempt is counted as dropped without being accepted, `accepted`
    is NOT in general equal to `delivered + dropped`. A hard sink error
    accounts every queued record as dropped; it is never treated as a success.
    A per-owner quota bounds how much of the buffer one VM can hold, so a
    single storming VM cannot consume the whole queue.
*/

#define _GNU_SOURCE

#include "qmeventd-log.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define QLOG_LINE_MAX 2048
#define QLOG_PENDING_MAX 8192
#define QLOG_MAX_RECS 256
#define QLOG_OWNER_LEN 16
/* one owner may hold at most half the queue: the rest stays available for
 * other VMs even while one of them storms */
#define QLOG_OWNER_QUOTA (QLOG_PENDING_MAX / 2)

static int log_fd = -1;
static int sink_is_socket = 0;

static char pending[QLOG_PENDING_MAX];
static size_t pending_len = 0;
static unsigned short rec_end[QLOG_MAX_RECS]; /* cumulative end offset of each queued record */
static char rec_owner[QLOG_MAX_RECS][QLOG_OWNER_LEN];
static unsigned char rec_report[QLOG_MAX_RECS]; /* 1 = internal LOG_DROPPED summary */
static unsigned rec_count = 0;

static int in_log = 0; /* re-entrancy guard: never recurse into logging */
static int reporting = 0;

static struct qmeventd_log_stats stats;

/*
 * Drop accounting has one live window and (at most) one in-flight summary:
 *
 *   live_*   drops not yet handed to a summary record.
 *   snap_*   the window moved into a summary record that was enqueued but not
 *            yet fully delivered. While it is set, further drops accrue in the
 *            (now empty) live window, so an old summary can neither absorb nor
 *            erase them and the next summary reports a disjoint window.
 *
 * Every drop is counted in stats.dropped_* exactly once, when it happens;
 * moving it into the snapshot or merging it back never touches stats again.
 */
static unsigned long long live_lines = 0;
static unsigned long long live_bytes = 0;
static time_t live_first = 0;
static time_t live_last = 0;

static unsigned long long snap_lines = 0;
static unsigned long long snap_bytes = 0;
static time_t snap_first = 0;
static time_t snap_last = 0;
static int snap_active = 0;

/* sink known to be dead: suppress idle wakeups until an explicit rebind */
static int sink_dead = 0;

static void discard_pending(void);

static int fd_is_socket(int fd) {
    int type = 0;
    socklen_t len = sizeof(type);
    if (fd < 0) {
        return 0;
    }
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0;
}

void qmeventd_log_init(int fd) {
    /*
     * Rebind the sink (startup, or after the previous one died). Records still
     * queued for the old sink can never be delivered, so account them instead
     * of silently dropping them from the counters; the accumulated unreported
     * drop window is preserved and reported on the new sink.
     */
    if (rec_count) {
        discard_pending();
    }
    log_fd = fd;
    sink_is_socket = fd_is_socket(fd);
    sink_dead = 0;
    pending_len = 0;
    rec_count = 0;
    in_log = 0;
    reporting = 0;
}

/*
 * Called in the cleanup child after fork() and before any failure output. The
 * child inherits the parent's queue and sink; both must be dropped so the
 * child neither resends the parent's queued bytes (which the parent will still
 * deliver) nor interleaves on the parent's stream. The caller rebinds the sink
 * to an independent stream (stderr, also wired to the journal by the unit).
 * The child starts from a clean slate: the inherited queue, the in-flight
 * summary and the parent's unreported drop window belong to the parent (which
 * keeps its own copy across fork) and must neither be re-emitted by the child
 * nor counted as a child-side loss.
 */
void qmeventd_log_child_reset(int fd) {
    log_fd = fd;
    sink_is_socket = fd_is_socket(fd);
    sink_dead = 0;
    pending_len = 0;
    rec_count = 0;
    in_log = 0;
    reporting = 0;
    live_lines = 0;
    live_bytes = 0;
    live_first = 0;
    live_last = 0;
    snap_lines = 0;
    snap_bytes = 0;
    snap_first = 0;
    snap_last = 0;
    snap_active = 0;
    memset(&stats, 0, sizeof(stats));
}

void qmeventd_log_get_stats(struct qmeventd_log_stats *out) {
    if (out) {
        *out = stats;
    }
}

void qmeventd_log_reset_stats(void) {
    memset(&stats, 0, sizeof(stats));
    live_lines = 0;
    live_bytes = 0;
    live_first = 0;
    live_last = 0;
    snap_lines = 0;
    snap_bytes = 0;
    snap_first = 0;
    snap_last = 0;
    snap_active = 0;
}

static const char *level_name(QLogLevel level) {
    switch (level) {
    case QLOG_WARNING:
        return "warning";
    case QLOG_ERROR:
        return "error";
    case QLOG_INFO:
    default:
        return "info";
    }
}

/* journal priority for a *bare* severity prefix (see the file header) */
static int level_priority(QLogLevel level) {
    switch (level) {
    case QLOG_WARNING:
        return 4;
    case QLOG_ERROR:
        return 3;
    case QLOG_INFO:
    default:
        return 6;
    }
}

/* VMID must be a plain decimal token; anything else is untrusted input */
static int token_is_vmid(const char *s) {
    const char *p;
    size_t n = 0;
    if (!s || !s[0]) {
        return 0;
    }
    for (p = s; *p; p++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
        if (++n > 15) {
            return 0;
        }
    }
    return 1;
}

/* source/event must be a single safe token: no control characters, no spaces */
static int token_is_name(const char *s) {
    const char *p;
    size_t n = 0;
    if (!s || !s[0]) {
        return 0;
    }
    for (p = s; *p; p++) {
        char c = *p;
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                 c == '_' || c == '-' || c == '.';
        if (!ok) {
            return 0;
        }
        if (++n > 31) {
            return 0;
        }
    }
    return 1;
}

static unsigned record_len(unsigned i) {
    return (unsigned)rec_end[i] - (i > 0 ? (unsigned)rec_end[i - 1] : 0u);
}

static void account_drop(unsigned long long lines, unsigned long long bytes) {
    struct timespec now;
    stats.dropped_lines += lines;
    stats.dropped_bytes += bytes;
    live_lines += lines;
    live_bytes += bytes;
    clock_gettime(CLOCK_REALTIME, &now);
    if (live_first == 0) {
        live_first = now.tv_sec;
    }
    live_last = now.tv_sec;
}

/* fold an undelivered in-flight summary back into the live window; its drops
 * were already counted in stats when they happened, so stats is not touched */
static void snapshot_to_live(void) {
    if (!snap_active) {
        return;
    }
    live_lines += snap_lines;
    live_bytes += snap_bytes;
    if (snap_first && (live_first == 0 || snap_first < live_first)) {
        live_first = snap_first;
    }
    if (snap_last > live_last) {
        live_last = snap_last;
    }
    snap_lines = 0;
    snap_bytes = 0;
    snap_first = 0;
    snap_last = 0;
    snap_active = 0;
}

/*
 * Drop every queued record. The in-flight summary (if any) is restored to the
 * live window first, so its window is never lost, then each *event* record
 * still queued is accounted once as dropped (summary records are not events).
 * `accepted` counts only records admitted into the pipeline, so it is NOT in
 * general equal to delivered + dropped: a rejected attempt (unsupported sink,
 * full buffer, owner quota) is counted as dropped without ever being accepted.
 */
static void discard_pending(void) {
    unsigned long long bytes = 0;
    unsigned long long lines = 0;
    unsigned i;

    snapshot_to_live();
    for (i = 0; i < rec_count; i++) {
        if (!rec_report[i]) {
            lines++;
            bytes += record_len(i);
        }
    }
    if (lines) {
        account_drop(lines, bytes);
    }
    rec_count = 0;
    pending_len = 0;
}

static void ack_snapshot(void) {
    snap_lines = 0;
    snap_bytes = 0;
    snap_first = 0;
    snap_last = 0;
    snap_active = 0;
}

/* consume the first k bytes of the queue, counting fully delivered records and
 * acknowledging an in-flight summary only once its whole record is consumed */
static void consume_front(size_t k) {
    unsigned delivered = 0;
    unsigned i;
    while (delivered < rec_count && (size_t)rec_end[delivered] <= k) {
        if (rec_report[delivered]) {
            ack_snapshot(); /* the summary record was fully written */
        } else {
            stats.delivered++;
        }
        delivered++;
    }
    if (delivered) {
        unsigned remain = rec_count - delivered;
        memmove(rec_end, rec_end + delivered, remain * sizeof(rec_end[0]));
        memmove(rec_owner, rec_owner + (size_t)delivered * QLOG_OWNER_LEN,
                (size_t)remain * QLOG_OWNER_LEN);
        memmove(rec_report, rec_report + delivered, remain * sizeof(rec_report[0]));
        rec_count = remain;
    }
    if (k > 0) {
        for (i = 0; i < rec_count; i++) {
            rec_end[i] = (unsigned short)((unsigned)rec_end[i] - (unsigned)k);
        }
        memmove(pending, pending + k, pending_len - k);
        pending_len -= k;
    }
}

static void flush_pending(void) {
    if (log_fd < 0 || !sink_is_socket) {
        return;
    }
    while (pending_len > 0) {
        ssize_t n = send(log_fd, pending, pending_len, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0) {
            consume_front((size_t)n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return; /* keep the remainder; retried on the next record or idle tick */
        }
        if (n < 0 && errno == ENOTSOCK) {
            /* the sink is not a socket after all: stop delivering */
            sink_is_socket = 0;
        }
        /* hard error (EPIPE/ECONNRESET/EBADF/...): the sink is gone. Account
         * what cannot be delivered, mark it dead so the daemon stops arming
         * idle wakeups, and wait for an explicit qmeventd_log_init() rebind. */
        discard_pending();
        sink_dead = 1;
        return;
    }
}

static void maybe_report_drops(void) {
    char line[QLOG_LINE_MAX];
    long long window;
    int n;

    if (reporting || sink_dead || !sink_is_socket || log_fd < 0) {
        return;
    }
    if (snap_active) {
        return; /* a summary is already in flight; wait for it to be acked */
    }
    if (live_lines == 0 || pending_len != 0) {
        return;
    }

    reporting = 1;
    window = (long long)(live_last - live_first);
    if (window < 0) {
        window = 0;
    }
    n = snprintf(
        line, sizeof(line),
        "<4>vmid=- qemu_pid=- peer_pid=- level=warning source=qmeventd "
        "event=LOG_DROPPED "
        "payload={\"lines\":%llu,\"bytes\":%llu,\"first_s\":%lld,\"last_s\":%lld,\"window_s\":%lld}\n",
        live_lines, live_bytes, (long long)live_first, (long long)live_last, window
    );
    if (n > 0 && (size_t)n <= QLOG_PENDING_MAX - pending_len && rec_count < QLOG_MAX_RECS) {
        /* Move the live window into the snapshot *before* enqueueing, so drops
         * that happen while this record is in flight accrue in the now-empty
         * live window and are reported separately. The snapshot is acked only
         * by consume_front() once the record was fully written, so a partial
         * write can neither duplicate nor erase it. The summary bypasses the
         * per-owner quota: loss must stay visible. */
        snap_lines = live_lines;
        snap_bytes = live_bytes;
        snap_first = live_first;
        snap_last = live_last;
        snap_active = 1;
        live_lines = 0;
        live_bytes = 0;
        live_first = 0;
        live_last = 0;

        memcpy(pending + pending_len, line, (size_t)n);
        pending_len += (size_t)n;
        rec_end[rec_count] = (unsigned short)pending_len;
        snprintf(rec_owner[rec_count], QLOG_OWNER_LEN, "%s", "-");
        rec_report[rec_count] = 1;
        rec_count++;
        flush_pending();
    }
    reporting = 0;
}

static size_t owner_pending_bytes(const char *owner) {
    size_t total = 0;
    unsigned i;
    for (i = 0; i < rec_count; i++) {
        if (!strcmp(rec_owner[i], owner)) {
            total += record_len(i);
        }
    }
    return total;
}

static int enqueue_and_flush(const char *line, size_t len, const char *owner) {
    const char *own = owner && owner[0] ? owner : "-";

    if (!sink_is_socket || log_fd < 0) {
        /* unsupported sink: never write, account the loss explicitly */
        account_drop(1, len);
        return 0;
    }

    if (len > QLOG_PENDING_MAX - pending_len) {
        /* the sink may have drained since the last attempt: push the backlog
         * first so a recovered journal is not starved by a full buffer */
        flush_pending();
    }
    if (len > QLOG_PENDING_MAX - pending_len || rec_count >= QLOG_MAX_RECS) {
        account_drop(1, len);
        return 0;
    }
    if (owner_pending_bytes(own) + len > QLOG_OWNER_QUOTA) {
        /* this owner already holds its share of the queue: drop visibly so a
         * single storming VM cannot starve the others */
        account_drop(1, len);
        return 0;
    }

    memcpy(pending + pending_len, line, len);
    pending_len += len;
    rec_end[rec_count] = (unsigned short)pending_len;
    snprintf(rec_owner[rec_count], QLOG_OWNER_LEN, "%s", own);
    rec_report[rec_count] = 0;
    rec_count++;
    stats.accepted++;
    flush_pending();
    return 1;
}

void qmeventd_log_flush_pending(void) {
    int saved_errno = errno;
    if (!in_log) {
        in_log = 1;
        flush_pending();
        maybe_report_drops();
        in_log = 0;
    }
    errno = saved_errno;
}

int qmeventd_log_has_pending(void) {
    if (log_fd < 0 || !sink_is_socket || sink_dead) {
        return 0;
    }
    return pending_len > 0 || live_lines > 0;
}

static void format_prefix(
    char *out,
    size_t outlen,
    const char *vmid,
    pid_t qemu_pid,
    pid_t peer_pid,
    QLogLevel level,
    const char *source,
    const char *event
) {
    char qpidbuf[24];
    char ppidbuf[24];

    if (qemu_pid > 0) {
        snprintf(qpidbuf, sizeof(qpidbuf), "%ld", (long)qemu_pid);
    } else {
        snprintf(qpidbuf, sizeof(qpidbuf), "-");
    }
    if (peer_pid > 0) {
        snprintf(ppidbuf, sizeof(ppidbuf), "%ld", (long)peer_pid);
    } else {
        snprintf(ppidbuf, sizeof(ppidbuf), "-");
    }
    snprintf(
        out, outlen, "<%d>vmid=%s qemu_pid=%s peer_pid=%s level=%s source=%s event=%s",
        level_priority(level), vmid ? vmid : "-", qpidbuf, ppidbuf, level_name(level),
        source ? source : "-", event ? event : "-"
    );
}

void qmeventd_log_event(
    const char *vmid,
    pid_t qemu_pid,
    pid_t peer_pid,
    QLogLevel level,
    const char *source,
    const char *event,
    struct json_object *payload
) {
    int saved_errno = errno;
    const char *safe_vmid;
    const char *safe_source;
    const char *safe_event;
    const char *raw_vmid = NULL;
    const char *raw_source = NULL;
    const char *raw_event = NULL;
    struct json_object *diag = NULL;
    struct json_object *body = payload;
    const char *pstr;
    char line[QLOG_LINE_MAX];
    size_t off;
    int n;

    if (in_log) {
        /* serialization/output failed while already logging: count, do not recurse */
        account_drop(1, 0);
        errno = saved_errno;
        return;
    }
    in_log = 1;

    /* push any backlog from a previously full sink before generating more */
    flush_pending();
    maybe_report_drops();

    /* Never interpolate untrusted text into the line structure: validate the
     * tokens and carry the raw value in the JSON body for diagnostics instead
     * of silently normalising it away. */
    safe_vmid = token_is_vmid(vmid) ? vmid : "-";
    safe_source = token_is_name(source) ? source : "-";
    safe_event = token_is_name(event) ? event : "-";
    if (vmid && vmid[0] && !token_is_vmid(vmid)) {
        raw_vmid = vmid;
    }
    if (source && source[0] && !token_is_name(source)) {
        raw_source = source;
    }
    if (event && event[0] && !token_is_name(event)) {
        raw_event = event;
    }
    if (raw_vmid || raw_source || raw_event) {
        diag = json_object_new_object();
        if (raw_vmid) {
            json_object_object_add(diag, "_untrusted_vmid", json_object_new_string(raw_vmid));
        }
        if (raw_source) {
            json_object_object_add(diag, "_untrusted_source", json_object_new_string(raw_source));
        }
        if (raw_event) {
            json_object_object_add(diag, "_untrusted_event", json_object_new_string(raw_event));
        }
        if (payload) {
            json_object_object_add(diag, "_payload", json_object_get(payload));
        }
        body = diag;
    }

    pstr = body ? json_object_to_json_string_ext(body, JSON_C_TO_STRING_PLAIN) : NULL;
    if (!pstr) {
        pstr = "null";
    }

    format_prefix(line, sizeof(line), safe_vmid, qemu_pid, peer_pid, level, safe_source, safe_event);
    off = strlen(line);
    n = snprintf(line + off, sizeof(line) - off, " payload=%s\n", pstr);
    if (n < 0 || (size_t)n >= sizeof(line) - off) {
        /* payload too large: replace it with a valid marker, never corrupt JSON */
        struct json_object *marker = json_object_new_object();
        const char *mstr;
        json_object_object_add(marker, "_truncated", json_object_new_boolean(1));
        json_object_object_add(
            marker, "_payload_bytes", json_object_new_int64((int64_t)strlen(pstr))
        );
        mstr = json_object_to_json_string_ext(marker, JSON_C_TO_STRING_PLAIN);
        format_prefix(
            line, sizeof(line), safe_vmid, qemu_pid, peer_pid, level, safe_source, safe_event
        );
        off = strlen(line);
        n = snprintf(line + off, sizeof(line) - off, " payload=%s\n", mstr ? mstr : "null");
        json_object_put(marker);
        if (n < 0 || (size_t)n >= sizeof(line) - off) {
            /* even the marker does not fit: count an explicit hard loss */
            account_drop(1, strlen(line));
            json_object_put(diag);
            in_log = 0;
            errno = saved_errno;
            return;
        }
        stats.truncated++;
    }

    enqueue_and_flush(line, off + (size_t)n, safe_vmid);

    maybe_report_drops();

    if (diag) {
        json_object_put(diag);
    }
    in_log = 0;
    errno = saved_errno;
}
