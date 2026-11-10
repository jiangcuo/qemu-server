// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    qmeventd journal logging, see qmeventd-log.h
*/

#define _GNU_SOURCE

#include "qmeventd-log.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define QLOG_LINE_MAX 4096

static int log_fd = -1;
static int sink_is_socket = 0;
static unsigned long long dropped = 0;

void qmeventd_log_init(int fd) {
    int type = 0;
    socklen_t len = sizeof(type);

    log_fd = fd;
    sink_is_socket = fd >= 0 && getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0;
}

unsigned long long qmeventd_log_dropped(void) { return dropped; }

static int level_prefix(QLogLevel level) {
    switch (level) {
    case QLOG_ERROR:
        return 3;
    case QLOG_WARNING:
        return 4;
    case QLOG_INFO:
    default:
        return 6;
    }
}

// only plain tokens go into the line structure, everything else is "-"
static const char *safe_token(const char *s) {
    if (!s || !*s || strlen(s) > 64) {
        return "-";
    }
    for (const char *p = s; *p; p++) {
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
              *p == '_' || *p == '-')) {
            return "-";
        }
    }
    return s;
}

void qmeventd_log_event(
    const char *vmid,
    pid_t qemu_pid,
    QLogLevel level,
    const char *source,
    const char *event,
    struct json_object *payload
) {
    char line[QLOG_LINE_MAX];
    char pidstr[16] = "-";
    const char *json = "{}";

    if (log_fd < 0) {
        return;
    }

    if (qemu_pid > 0) {
        snprintf(pidstr, sizeof(pidstr), "%d", qemu_pid);
    }
    if (payload) {
        json = json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PLAIN);
    }

    int len = snprintf(
        line, sizeof(line), "<%d>vmid=%s qemu_pid=%s source=%s event=%s payload=%s\n",
        level_prefix(level), safe_token(vmid), pidstr, safe_token(source), safe_token(event), json
    );
    if (len < 0) {
        return;
    }
    if ((size_t)len >= sizeof(line)) {
        // keep the line structure intact, mark the payload as truncated
        len = sizeof(line) - 1;
        static const char trunc[] = "...(truncated)\n";
        memcpy(line + len - (sizeof(trunc) - 1), trunc, sizeof(trunc) - 1);
    }

    ssize_t res;
    if (sink_is_socket) {
        do {
            res = send(log_fd, line, (size_t)len, MSG_DONTWAIT | MSG_NOSIGNAL);
        } while (res < 0 && errno == EINTR);
    } else {
        // foreground/test mode: stdout is a tty, pipe or file
        res = write(log_fd, line, (size_t)len);
    }
    if (res != len) {
        dropped++;
        if (sink_is_socket && res > 0) {
            // terminate the partial line so the next record starts cleanly
            (void)send(log_fd, "\n", 1, MSG_DONTWAIT | MSG_NOSIGNAL);
        }
    }
}
