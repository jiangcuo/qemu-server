// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    qmeventd key-event journal logging.

    Emits one log record per line on a dedicated fd (the daemon's standard
    output, which systemd connects to the journal). The record carries a bare
    severity prefix (<6>/<4>/<3>) so that SyslogLevelPrefix=yes maps the
    textual level to the journal PRIORITY. Delivery to the sink is best effort
    and never blocks the control loop.
*/

#ifndef QMEVENTD_LOG_H
#define QMEVENTD_LOG_H

#include <json.h>
#include <sys/types.h>

typedef enum {
    QLOG_INFO,
    QLOG_WARNING,
    QLOG_ERROR
} QLogLevel;

struct qmeventd_log_stats {
    unsigned long long accepted;      /* records admitted to the pipeline */
    unsigned long long delivered;     /* records fully written to the sink */
    unsigned long long dropped_lines; /* records that will never be delivered */
    unsigned long long dropped_bytes; /* bytes of dropped records */
    unsigned long long truncated;     /* records emitted with a truncated payload */
};

/*
 * Bind the log sink. Called once at startup with STDOUT_FILENO. Only socket
 * sinks are supported (systemd always backs StandardOutput=journal with an
 * AF_UNIX socket); any other fd disables delivery and every record is
 * accounted as dropped. Passing a negative fd also disables output (tests).
 */
void qmeventd_log_init(int fd);

/*
 * Emit one key-event record. `payload` is serialized compactly and must be the
 * complete information from the source (for QMP events: the whole received
 * object, so event/data/timestamp are preserved). Payload may be NULL. An
 * unsafe vmid/source/event is rendered as "-" and its raw value is preserved
 * inside the JSON payload instead of being interpolated into the line.
 */
void qmeventd_log_event(
    const char *vmid,
    pid_t qemu_pid,
    pid_t peer_pid,
    QLogLevel level,
    const char *source,
    const char *event,
    struct json_object *payload
);

/*
 * True while a record backlog and/or an undelivered drop summary is wait-
 * ing. The daemon uses this to arm a short epoll timeout so a recovered
 * journal is drained even when no new VM event arrives.
 */
int qmeventd_log_has_pending(void);

/* Flush the backlog and report pending drops. Safe to call every loop. */
void qmeventd_log_flush_pending(void);

/*
 * Reset the logger in a forked cleanup child before it emits any failure
 * output: the inherited parent queue is discarded and the sink is rebound to
 * `fd` (the caller uses STDERR_FILENO, also wired to the journal). This keeps
 * the child from resending the parent's queued records or interleaving on the
 * parent's stream.
 */
void qmeventd_log_child_reset(int fd);

void qmeventd_log_get_stats(struct qmeventd_log_stats *out);
void qmeventd_log_reset_stats(void);

#endif /* QMEVENTD_LOG_H */
