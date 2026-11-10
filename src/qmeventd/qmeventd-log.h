// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    qmeventd journal logging.

    One record per line on standard output, which systemd connects to the
    journal. Each line starts with a bare severity prefix (<6>, <4>, <3>) so
    that SyslogLevelPrefix=yes maps it to the journal PRIORITY.
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

/* Bind the sink, normally STDOUT_FILENO. A negative fd disables output. */
void qmeventd_log_init(int fd);

/*
 * Emit one record:
 *   vmid=<VMID|-> qemu_pid=<PID|-> source=<SRC> event=<NAME> payload=<JSON>
 * The payload is serialized by json-c on a single line, so guest supplied
 * strings cannot inject additional records. Never blocks: if the journal
 * socket is full the record is dropped and counted.
 */
void qmeventd_log_event(
    const char *vmid,
    pid_t qemu_pid,
    QLogLevel level,
    const char *source,
    const char *event,
    struct json_object *payload
);

/* number of records dropped because the sink was not writable */
unsigned long long qmeventd_log_dropped(void);

#endif /* QMEVENTD_LOG_H */
