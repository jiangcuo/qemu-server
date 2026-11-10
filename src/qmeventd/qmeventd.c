// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    Copyright (C) 2018 - 2021 Proxmox Server Solutions GmbH

    Author: Dominik Csapak <d.csapak@proxmox.com>
    Author: Stefan Reiter <s.reiter@proxmox.com>

    Description:

    qmeventd listens on a given socket, and waits for qemu processes to
    connect. After accepting a connection qmeventd waits for shutdown events
    followed by the closing of the socket. Once that happens `qm cleanup` will
    be executed with following three arguments:
    VMID <graceful> <guest>
    Where `graceful` can be `1` or `0` depending if shutdown event was observed
    before the socket got closed. The second parameter `guest` is also boolean
    `1` or `0` depending if the shutdown was requested from the guest OS
    (i.e., the "inside").
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <gmodule.h>
#include <json.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "qmeventd.h"
#include "qmeventd-capture.h"

#define DEFAULT_KILL_TIMEOUT 60

static int verbose = 0;
static int kill_timeout = DEFAULT_KILL_TIMEOUT;
static int epoll_fd = 0;
static const char *progname;
GHashTable *vm_clients; // key=vmid (freed on remove), value=*Client (free manually)
GSList *forced_cleanups;
static int needs_cleanup = 0;

/* Private supervised capture-worker bridge. NULL in unit tests that do not
 * exercise it, and never required for the QMP control path. */
static struct qmev_capture *capture_mod = NULL;

/*
 * Helper functions
 */

static void usage() {
    fprintf(stderr, "Usage: %s [-f] [-v] PATH\n", progname);
    fprintf(stderr, "  -f       run in foreground (default: false)\n");
    fprintf(stderr, "  -v       verbose (default: false)\n");
    fprintf(stderr, "  -t <s>   kill timeout (default: %ds)\n", DEFAULT_KILL_TIMEOUT);
    fprintf(stderr, "  PATH     use PATH for socket\n");
}

static pid_t get_pid_from_fd(int fd) {
    struct ucred credentials = {.pid = 0, .uid = 0, .gid = 0};
    socklen_t len = sizeof(struct ucred);
    log_neg(getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &len), "getsockopt");
    return credentials.pid;
}

/*
 * parses the vmid from the qemu.slice entry of /proc/<pid>/cgroup
 */
static unsigned long get_vmid_from_pid(pid_t pid) {
    char filename[32] = {0};
    int len = snprintf(filename, sizeof(filename), "/proc/%d/cmdline", pid);
    if (len < 0) {
        fprintf(stderr, "error during snprintf for %d: %s\n", pid, strerror(errno));
        return 0;
    }
    if ((size_t)len >= sizeof(filename)) {
        fprintf(stderr, "error: pid %d too long\n", pid);
        return 0;
    }
    FILE *fp = fopen(filename, "re");
    if (fp == NULL) {
        fprintf(stderr, "error opening %s: %s\n", filename, strerror(errno));
        return 0;
    }

    unsigned long vmid = 0;
    char *buf = NULL;
    size_t buflen = 0;

    while (getdelim(&buf, &buflen, '\0', fp) >= 0) {
        if (strcmp(buf, "-pidfile")) {
            continue;
        }

        if (getdelim(&buf, &buflen, '\0', fp) < 0) {
            break;
        }

        char *vmid_start = strrchr(buf, '/');
        if (!vmid_start) {
            fprintf(stderr, "unexpected pidfile option %s\n", buf);
            break;
        }
        vmid_start++;

        if (vmid_start[0] == '-' || vmid_start[0] == '\0') {
            fprintf(stderr, "invalid vmid in pidfile option %s\n", buf);
            break;
        }

        errno = 0;
        char *endptr = NULL;
        vmid = strtoul(vmid_start, &endptr, 10);
        if (!endptr || strcmp(endptr, ".pid")) {
            fprintf(stderr, "unexpected pidfile option %s\n", buf);
            vmid = 0;
            break;
        }
        if (errno != 0) {
            vmid = 0;
        }

        break;
    }

    if (errno) {
        fprintf(stderr, "error parsing vmid for %d: %s\n", pid, strerror(errno));
    } else if (!vmid) {
        fprintf(stderr, "error parsing vmid for %d: no matching pidfile option\n", pid);
    }

    free(buf);
    fclose(fp);
    return vmid;
}

static bool must_write(int fd, const char *buf, size_t len) {
    ssize_t wlen;
    do {
        wlen = write(fd, buf, len);
    } while (wlen < 0 && errno == EINTR);

    return (wlen == (ssize_t)len);
}

/*
 * qmp handling functions
 */

/*
 * Whitelist of QMP events that are worth a journal record by default.
 * Everything else stays silent (available via -v only), so the normal read
 * loop never floods the journal.
 */
struct qmp_event_level {
    const char *name;
    QLogLevel level;
};

static const struct qmp_event_level qmp_event_levels[] = {
    {"SHUTDOWN", QLOG_INFO},
    {"RESET", QLOG_INFO},
    {"STOP", QLOG_INFO},
    {"RESUME", QLOG_INFO},
    {"SUSPEND", QLOG_INFO},
    {"SUSPEND_DISK", QLOG_INFO},
    {"WAKEUP", QLOG_INFO},
    {"GUEST_PANICKED", QLOG_ERROR},
    /* GUEST_CRASHLOADED is the Windows pvpanic crash-dump notification. It is
     * a separate fact from GUEST_PANICKED and does not mean the dump was
     * written; the dump path must not be filtered out of the journal. */
    {"GUEST_CRASHLOADED", QLOG_ERROR},
    {"BLOCK_IO_ERROR", QLOG_ERROR},
    {"BLOCK_JOB_ERROR", QLOG_ERROR},
    {"WATCHDOG", QLOG_WARNING},
};

static const struct qmp_event_level *lookup_qmp_event_level(const char *name) {
    size_t i;
    if (!name) {
        return NULL;
    }
    for (i = 0; i < sizeof(qmp_event_levels) / sizeof(qmp_event_levels[0]); i++) {
        if (!strcmp(name, qmp_event_levels[i].name)) {
            return &qmp_event_levels[i];
        }
    }
    return NULL;
}

/*
 * Best-effort vmid for logging. A connection that is not (yet) identified
 * must never inherit another VM's id.
 */
static const char *client_vmid(struct Client *client) {
    if (client->type == CLIENT_QEMU && client->qemu.vmid[0]) {
        return client->qemu.vmid;
    }
    if (client->type == CLIENT_VZDUMP && client->vzdump.vmid[0]) {
        return client->vzdump.vmid;
    }
    if (client->qemu.vmid[0]) {
        return client->qemu.vmid;
    }
    /* a connection that already parsed a claimed VMID (e.g. a VZDump
     * handshake that failed validation) keeps it for diagnostics */
    if (client->vzdump.vmid[0]) {
        return client->vzdump.vmid;
    }
    return NULL;
}

/*
 * The QEMU PID for a connection, never the peer PID. For a VZDump connection
 * the QEMU process is looked up through the VMID->client map; if there is no
 * registered QEMU (unknown/live-restore case) this is 0, which the logger
 * renders as "-".
 */
static pid_t client_qemu_pid(struct Client *client) {
    if (client->type == CLIENT_QEMU) {
        return client->pid;
    }
    if (client->type == CLIENT_VZDUMP && client->vzdump.vmid[0]) {
        struct Client *vmc = (struct Client *)g_hash_table_lookup(vm_clients, client->vzdump.vmid);
        if (vmc) {
            return vmc->pid;
        }
    }
    return 0;
}

/*
 * A connection that keeps sending garbage must not flood the journal. The
 * first protocol error is recorded in full; repeats are suppressed and
 * reported in a summary every PROTO_SUPPRESS_REPORT_EVERY repeats and once
 * more when the connection closes. Output is therefore bounded to one summary
 * per threshold, with the real count and the first/last error timestamps.
 */
#define PROTO_SUPPRESS_REPORT_EVERY 100

static const char *protocol_error_source(struct Client *client) {
    return client->type == CLIENT_VZDUMP ? "vzdump" : "qmeventd";
}

static void emit_proto_summary(struct Client *client) {
    struct json_object *s;
    const char *source = client->proto_source ? client->proto_source : "qmeventd";
    if (client->proto_suppressed == 0) {
        return;
    }
    s = json_object_new_object();
    json_object_object_add(s, "reason", json_object_new_string("repeated protocol errors"));
    json_object_object_add(
        s, "suppressed", json_object_new_int64((int64_t)client->proto_suppressed)
    );
    json_object_object_add(s, "first_s", json_object_new_int64((int64_t)client->proto_first));
    json_object_object_add(s, "last_s", json_object_new_int64((int64_t)client->proto_last));
    qmeventd_log_event(
        client_vmid(client), client_qemu_pid(client), client->pid, QLOG_WARNING, source,
        "PROTOCOL_ERROR", s
    );
    json_object_put(s);
    client->proto_suppressed = 0;
    client->proto_first = 0;
}

static void log_protocol_error(
    struct Client *client, const char *source, const char *reason, const char *detail
) {
    struct json_object *payload = json_object_new_object();
    time_t now = time(NULL);
    json_object_object_add(payload, "reason", json_object_new_string(reason));
    if (detail) {
        json_object_object_add(payload, "detail", json_object_new_string(detail));
    }

    client->proto_errors++;
    if (client->proto_errors == 1) {
        /* first occurrence is always recorded in full */
        client->proto_source = source;
        json_object_object_add(payload, "count", json_object_new_int(1));
        qmeventd_log_event(
            client_vmid(client), client_qemu_pid(client), client->pid, QLOG_WARNING, source,
            "PROTOCOL_ERROR", payload
        );
        json_object_put(payload);
        return;
    }

    /* further repeats are suppressed and only summarised, never silently lost */
    client->proto_suppressed++;
    if (client->proto_first == 0) {
        client->proto_first = now;
    }
    client->proto_last = now;
    json_object_put(payload);
    if (client->proto_suppressed >= PROTO_SUPPRESS_REPORT_EVERY) {
        emit_proto_summary(client);
    }
}

static void send_qmp_cmd(struct Client *client, const char *buf, size_t len) {
    if (!must_write(client->fd, buf, len - 1)) {
        fprintf(stderr, "%s: cannot send QMP message\n", client->qemu.vmid);
        cleanup_client(client);
    }
}

void handle_qmp_handshake(struct Client *client) {
    VERBOSE_PRINT("pid%d: got QMP handshake, assuming QEMU client\n", client->pid);

    // extract vmid from cmdline, now that we know it's a QEMU process
    unsigned long vmid = get_vmid_from_pid(client->pid);
    int res = snprintf(client->qemu.vmid, sizeof(client->qemu.vmid), "%lu", vmid);
    if (vmid == 0 || res < 0 || res >= (int)sizeof(client->qemu.vmid)) {
        /* no valid vmid was resolved: never reuse the "0" placeholder */
        client->qemu.vmid[0] = '\0';
        log_protocol_error(
            client, protocol_error_source(client), "could not determine vmid from QEMU pid", NULL
        );
        cleanup_client(client);
        return;
    }

    VERBOSE_PRINT("pid%d: assigned VMID: %s\n", client->pid, client->qemu.vmid);
    client->type = CLIENT_QEMU;
    if (!g_hash_table_insert(vm_clients, strdup(client->qemu.vmid), client)) {
        // not fatal, just means backup handling won't work
        fprintf(stderr, "%s: could not insert client into VMID->client table\n", client->qemu.vmid);
    }

    qmeventd_log_event(
        client->qemu.vmid, client->pid, client->pid, QLOG_INFO, "qmeventd", "QMP_CONNECTED", NULL
    );

    /* Forward the trusted identity (vmid + QEMU pid + /proc starttime) to the
     * capture worker. A new connection starts a new generation. If the process
     * start time cannot be read the identity is not trusted and is not sent. */
    if (capture_mod) {
        char starttime[24];
        if (qmev_read_starttime(client->pid, starttime, sizeof(starttime)) == 0) {
            qmev_capture_observe_connected(
                capture_mod, client->qemu.vmid, client->pid, starttime
            );
        }
    }

    static const char qmp_answer[] = "{\"execute\":\"qmp_capabilities\"}\n";
    send_qmp_cmd(client, qmp_answer, sizeof(qmp_answer));
}

/*
 * Per-connection storm control for whitelisted QMP events. Normal (low
 * frequency) events pass through untouched -- RESET is deliberately not
 * de-duplicated -- but a single connection may emit at most LOG_STORM_BUDGET
 * records per LOG_STORM_WINDOW. The suppressed remainder is summarised with
 * the real count and first/last timestamps, so a storm is visible without
 * being allowed to fill the journal. This is scoped per connection, so one VM
 * cannot take the budget of another.
 */
#define LOG_STORM_BUDGET 200
#define LOG_STORM_WINDOW 10
#define LOG_STORM_SUMMARY_EVERY 500

static void emit_storm_summary(struct Client *client) {
    struct json_object *s;
    if (!client->qemu.vmid[0] || client->storm_suppressed == 0) {
        client->storm_suppressed = 0;
        return;
    }
    s = json_object_new_object();
    json_object_object_add(
        s, "event",
        json_object_new_string(client->storm_last_event[0] ? client->storm_last_event : "?")
    );
    json_object_object_add(
        s, "suppressed", json_object_new_int64((int64_t)client->storm_suppressed)
    );
    json_object_object_add(s, "first_s", json_object_new_int64((int64_t)client->storm_first));
    json_object_object_add(s, "last_s", json_object_new_int64((int64_t)client->storm_last));
    qmeventd_log_event(
        client->qemu.vmid, client->pid, client->pid, QLOG_WARNING, "qmp", "LOG_SUPPRESSED", s
    );
    json_object_put(s);
    client->storm_suppressed = 0;
}

static void log_qmp_event_bounded(
    struct Client *client, QLogLevel level, const char *event, struct json_object *obj
) {
    time_t now = time(NULL);

    if (client->storm_window_start == 0 || now - client->storm_window_start >= LOG_STORM_WINDOW) {
        if (client->storm_suppressed > 0) {
            emit_storm_summary(client);
        }
        client->storm_window_start = now;
        client->storm_count = 0;
    }

    if (client->storm_count < LOG_STORM_BUDGET) {
        client->storm_count++;
        qmeventd_log_event(
            client->qemu.vmid[0] ? client->qemu.vmid : NULL, client->pid, client->pid, level,
            "qmp", event, obj
        );
        return;
    }

    if (client->storm_suppressed == 0) {
        client->storm_first = now;
    }
    client->storm_last = now;
    client->storm_suppressed++;
    snprintf(client->storm_last_event, sizeof(client->storm_last_event), "%s", event ? event : "?");
    if (client->storm_suppressed >= LOG_STORM_SUMMARY_EVERY) {
        emit_storm_summary(client);
    }
}

void handle_qmp_event(struct Client *client, struct json_object *obj) {
    struct json_object *event;
    const struct qmp_event_level *evlevel;
    if (!json_object_object_get_ex(obj, "event", &event)) {
        return;
    }

    /* Record the fact that the event was received before the business logic
     * below may ignore it (e.g. events arriving after termination). */
    evlevel = lookup_qmp_event_level(json_object_get_string(event));
    if (evlevel) {
        log_qmp_event_bounded(client, evlevel->level, json_object_get_string(event), obj);
    } else {
        VERBOSE_PRINT("%s: got QMP event: %s\n", client->qemu.vmid, json_object_get_string(event));
    }

    /* Forward lifecycle/panic/migration events to the capture worker,
     * independent of the journal logging above (and its rate limiting). Only a
     * validated CLIENT_QEMU identity is forwarded; an unknown vmid is dropped
     * by the capture bridge itself. */
    if (capture_mod && client->qemu.vmid[0]) {
        qmev_capture_observe_event(
            capture_mod, client->qemu.vmid, json_object_get_string(event), obj
        );
    }

    if (client->state == STATE_TERMINATING) {
        // QEMU sometimes sends a second SHUTDOWN after SIGTERM, ignore
        VERBOSE_PRINT("%s: event was after termination, ignoring\n", client->qemu.vmid);
        return;
    }

    // event, check if shutdown and get guest parameter
    if (!strcmp(json_object_get_string(event), "SHUTDOWN")) {
        client->qemu.graceful = 1;
        struct json_object *data;
        struct json_object *guest;
        if (json_object_object_get_ex(obj, "data", &data) &&
            json_object_object_get_ex(data, "guest", &guest)) {
            client->qemu.guest = (unsigned short)json_object_get_boolean(guest);
        }

        // check if a backup is running and kill QEMU process if not
        terminate_check(client);
    }
}

void terminate_check(struct Client *client) {
    if (client->state != STATE_IDLE) {
        // if we're already in a request, queue this one until after
        VERBOSE_PRINT("%s: terminate_check queued\n", client->qemu.vmid);
        client->qemu.term_check_queued = true;
        return;
    }

    client->qemu.term_check_queued = false;

    VERBOSE_PRINT("%s: query-status\n", client->qemu.vmid);
    client->state = STATE_EXPECT_STATUS_RESP;
    static const char qmp_req[] = "{\"execute\":\"query-status\"}\n";
    send_qmp_cmd(client, qmp_req, sizeof(qmp_req));
}

void handle_qmp_return(struct Client *client, struct json_object *data, bool error) {
    if (error) {
        /* record the full error object (class/desc); this is a command error,
         * not a transport failure */
        qmeventd_log_event(
            client->qemu.vmid[0] ? client->qemu.vmid : NULL, client->pid, client->pid,
            QLOG_ERROR, "qmeventd", "QMP_ERROR", data
        );
        client->state = STATE_IDLE;
        goto out;
    }

    struct json_object *status;
    json_bool has_status = data && json_object_object_get_ex(data, "status", &status);

    bool active = false;
    if (has_status) {
        const char *status_str = json_object_get_string(status);
        active =
            status_str && (!strcmp(status_str, "running") || !strcmp(status_str, "paused") ||
                           !strcmp(status_str, "suspended") || !strcmp(status_str, "prelaunch"));
    }

    switch (client->state) {
    case STATE_EXPECT_STATUS_RESP:
        client->state = STATE_IDLE;
        if (has_status) {
            const char *status_str = json_object_get_string(status);
            if (status_str && strcmp(status_str, client->qemu.last_status)) {
                struct json_object *s = json_object_new_object();
                json_object_object_add(s, "status", json_object_new_string(status_str));
                qmeventd_log_event(
                    client->qemu.vmid[0] ? client->qemu.vmid : NULL, client->pid, client->pid,
                    QLOG_INFO, "qmeventd", "VM_STATUS_CHANGED", s
                );
                json_object_put(s);
                snprintf(
                    client->qemu.last_status, sizeof(client->qemu.last_status), "%s", status_str
                );
            }
        }
        if (active) {
            client->qemu.term_deferred = false;
        } else if (!client->qemu.backup) {
            terminate_client(client);
        } else {
            // if we're in a backup, don't do anything, vzdump will notify
            // us when the backup finishes
            if (!client->qemu.term_deferred) {
                struct json_object *d = json_object_new_object();
                json_object_object_add(d, "backup", json_object_new_boolean(1));
                qmeventd_log_event(
                    client->qemu.vmid[0] ? client->qemu.vmid : NULL, client->pid, client->pid,
                    QLOG_INFO, "qmeventd", "TERMINATION_DEFERRED", d
                );
                json_object_put(d);
                client->qemu.term_deferred = true;
            }
        }
        break;

    // this means we received the empty return from our handshake answer
    case STATE_HANDSHAKE:
        client->state = STATE_IDLE;
        VERBOSE_PRINT("%s: QMP handshake complete\n", client->qemu.vmid);
        break;

    // we expect an empty return object after sending quit
    case STATE_TERMINATING:
        break;
    case STATE_IDLE:
        VERBOSE_PRINT("%s: spurious return value received\n", client->qemu.vmid);
        break;
    }

out:
    if (client->qemu.term_check_queued) {
        terminate_check(client);
    }
}

/*
 * VZDump specific client functions
 */

void handle_vzdump_handshake(struct Client *client, struct json_object *data) {
    client->state = STATE_IDLE;

    struct json_object *vmid_obj;
    json_bool has_vmid = data && json_object_object_get_ex(data, "vmid", &vmid_obj);

    if (!has_vmid) {
        log_protocol_error(client, "vzdump", "invalid vzdump handshake: no vmid", NULL);
        return;
    }

    const char *vmid_str = json_object_get_string(vmid_obj);

    if (!vmid_str) {
        log_protocol_error(client, "vzdump", "invalid vzdump handshake: vmid is not a string", NULL);
        return;
    }

    int res = snprintf(client->vzdump.vmid, sizeof(client->vzdump.vmid), "%s", vmid_str);
    if (res < 0 || res >= (int)sizeof(client->vzdump.vmid)) {
        /* never keep a truncated VMID: it would be attributed to a wrong VM */
        client->vzdump.vmid[0] = '\0';
        log_protocol_error(client, "vzdump", "invalid vzdump handshake: vmid too long", NULL);
        return;
    }

    struct Client *vmc = (struct Client *)g_hash_table_lookup(vm_clients, client->vzdump.vmid);
    if (vmc) {
        vmc->qemu.backup = true;

        // only mark as VZDUMP once we have set everything up, otherwise 'cleanup'
        // might try to access an invalid value
        client->type = CLIENT_VZDUMP;
        /* this is the start of backup/restore protection, NOT proof of a
         * successful backup: the same protocol is used by live restore and
         * the guard is only released when the connection closes */
        struct json_object *p = json_object_new_object();
        json_object_object_add(p, "vmid", json_object_new_string(client->vzdump.vmid));
        json_object_object_add(p, "protocol", json_object_new_string("vzdump"));
        qmeventd_log_event(
            client->vzdump.vmid, vmc->pid, client->pid, QLOG_INFO, "vzdump", "BACKUP_GUARD_ENTER", p
        );
        json_object_put(p);
        /* the backup observation carries the mapped QEMU identity, never the
         * backup helper's PID */
        if (capture_mod) {
            qmev_capture_observe_backup(capture_mod, client->vzdump.vmid, true);
        }
    } else {
        log_protocol_error(client, "vzdump", "vzdump guard requested for unregistered VM", NULL);
    }
}

/*
 * client management functions
 */

void add_new_client(int client_fd) {
    struct Client *client = calloc(1, sizeof(struct Client));
    if (client == NULL) {
        fprintf(stderr, "could not add new client - allocation failed!\n");
        fflush(stderr);
        return;
    }
    client->state = STATE_HANDSHAKE;
    client->type = CLIENT_NONE;
    client->fd = client_fd;
    client->pid = get_pid_from_fd(client_fd);
    if (client->pid == 0) {
        fprintf(stderr, "could not get pid from client\n");
        goto err;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = client;
    int res = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
    if (res < 0) {
        perror("epoll_ctl client add");
        goto err;
    }

    VERBOSE_PRINT("added new client, pid: %d\n", client->pid);

    return;
err:
    (void)close(client_fd);
    free(client);
}

static void cleanup_qemu_client(struct Client *client) {
    unsigned short graceful = client->qemu.graceful;
    unsigned short guest = client->qemu.guest;
    char vmid[sizeof(client->qemu.vmid)];
    strncpy(vmid, client->qemu.vmid, sizeof(vmid));
    g_hash_table_remove(vm_clients, &vmid); // frees key, ignore errors

    /* a cleanup run is requested here; a successful fork/exec is only proof
     * that the request was made, not that cleanup completed */
    struct json_object *p = json_object_new_object();
    json_object_object_add(p, "graceful", json_object_new_int(graceful ? 1 : 0));
    json_object_object_add(p, "guest", json_object_new_int(guest ? 1 : 0));
    qmeventd_log_event(
        vmid[0] ? vmid : NULL, client->pid, client->pid, QLOG_INFO, "qmeventd", "CLEANUP_REQUESTED",
        p
    );
    json_object_put(p);

    int pid = fork();
    if (pid < 0) {
        struct json_object *e = json_object_new_object();
        json_object_object_add(e, "phase", json_object_new_string("fork"));
        json_object_object_add(e, "error", json_object_new_string(strerror(errno)));
        qmeventd_log_event(
            vmid[0] ? vmid : NULL, client->pid, client->pid, QLOG_ERROR, "qmeventd",
            "CLEANUP_START_ERROR", e
        );
        json_object_put(e);
        return;
    }
    if (pid == 0) {
        char *script = "/usr/sbin/qm";

        char *args[] = {script, "cleanup", vmid, graceful ? "1" : "0", guest ? "1" : "0", NULL};

        execvp(script, args);
        /* Rebind to an independent stream and drop the parent's inherited
         * queue before logging: the parent still owns and will deliver that
         * queue, so resending it here would duplicate bytes on the same
         * stream. Keep the known VMID and QEMU PID in the failure record. */
        qmeventd_log_child_reset(STDERR_FILENO);
        struct json_object *e = json_object_new_object();
        json_object_object_add(e, "phase", json_object_new_string("exec"));
        json_object_object_add(e, "script", json_object_new_string(script));
        json_object_object_add(e, "error", json_object_new_string(strerror(errno)));
        qmeventd_log_event(
            vmid[0] ? vmid : NULL, client->pid, client->pid, QLOG_ERROR, "qmeventd",
            "CLEANUP_START_ERROR", e
        );
        json_object_put(e);
        _exit(1);
    }
}

void cleanup_client(struct Client *client) {
    log_neg(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client->fd, NULL), "epoll del");
    (void)close(client->fd);

    struct Client *vmc;
    switch (client->type) {
    case CLIENT_QEMU:
        /* forward the disconnect before the parent client is destroyed, so the
         * worker can drop its per-generation state */
        if (capture_mod && client->qemu.vmid[0]) {
            qmev_capture_observe_disconnected(capture_mod, client->qemu.vmid);
        }
        /* the peer closed the socket; this alone does not prove QEMU crashed */
        qmeventd_log_event(
            client->qemu.vmid[0] ? client->qemu.vmid : NULL, client->pid, client->pid, QLOG_INFO,
            "qmeventd", "QMP_DISCONNECTED", NULL
        );
        cleanup_qemu_client(client);
        break;

    case CLIENT_VZDUMP:
        vmc = (struct Client *)g_hash_table_lookup(vm_clients, client->vzdump.vmid);
        if (vmc) {
            /* guard released; this is not proof that the backup succeeded */
            qmeventd_log_event(
                client->vzdump.vmid, vmc->pid, client->pid, QLOG_INFO, "vzdump",
                "BACKUP_GUARD_LEAVE", NULL
            );
            if (capture_mod) {
                qmev_capture_observe_backup(capture_mod, client->vzdump.vmid, false);
            }
            vmc->qemu.backup = false;
            terminate_check(vmc);
        }
        break;

    case CLIENT_NONE:
        // do nothing, only close socket
        break;
    }

    /* report suppressed repeats and any suppressed QMP storm before the
     * connection state is gone */
    if (client->type == CLIENT_QEMU) {
        emit_storm_summary(client);
    }
    emit_proto_summary(client);

    if (client->pidfd > 0) {
        (void)close(client->pidfd);
    }
    forced_cleanups = g_slist_remove(forced_cleanups, client);
    free(client);
}

void terminate_client(struct Client *client) {
    client->state = STATE_TERMINATING;

    // open a pidfd before kill for later cleanup
    int pidfd = pidfd_open(client->pid, 0);
    if (pidfd < 0) {
        switch (errno) {
        case ESRCH:
            // process already dead for some reason, cleanup done
            VERBOSE_PRINT(
                "%s: failed to open pidfd, process already dead (pid %d)\n", client->qemu.vmid,
                client->pid
            );
            return;

        // otherwise fall back to just using the PID directly, but don't
        // print if we only failed because we're running on an older kernel
        case ENOSYS:
            break;
        default:
            perror("failed to open QEMU pidfd for cleanup");
            break;
        }
    }

    // try to send a 'quit' command first, fallback to SIGTERM of the pid
    static const char qmp_quit_command[] = "{\"execute\":\"quit\"}\n";
    {
        struct json_object *p = json_object_new_object();
        json_object_object_add(p, "via", json_object_new_string("qmp"));
        qmeventd_log_event(
            client->qemu.vmid[0] ? client->qemu.vmid : NULL, client->pid, client->pid, QLOG_INFO,
            "qmeventd", "QMP_QUIT_REQUESTED", p
        );
        json_object_put(p);
    }
    if (!must_write(client->fd, qmp_quit_command, sizeof(qmp_quit_command) - 1)) {
        struct json_object *p = json_object_new_object();
        json_object_object_add(p, "pid", json_object_new_int((int)client->pid));
        json_object_object_add(p, "reason", json_object_new_string("qmp quit not delivered"));
        qmeventd_log_event(
            client->qemu.vmid[0] ? client->qemu.vmid : NULL, client->pid, client->pid, QLOG_WARNING,
            "qmeventd", "SIGTERM_FALLBACK", p
        );
        json_object_put(p);
        int err = kill(client->pid, SIGTERM);
        if (err < 0) {
            struct json_object *e = json_object_new_object();
            json_object_object_add(e, "pid", json_object_new_int((int)client->pid));
            json_object_object_add(
                e, "signal", json_object_new_string("SIGTERM")
            );
            json_object_object_add(e, "error", json_object_new_string(strerror(errno)));
            qmeventd_log_event(
                client->qemu.vmid[0] ? client->qemu.vmid : NULL, client->pid, client->pid,
                QLOG_ERROR, "qmeventd", "SIGTERM_FALLBACK", e
            );
            json_object_put(e);
        }
    }

    time_t timeout = time(NULL) + kill_timeout;

    client->pidfd = pidfd;
    client->timeout = timeout;

    forced_cleanups = g_slist_prepend(forced_cleanups, (void *)client);
    needs_cleanup = 1;
}

void handle_client(struct Client *client) {
    VERBOSE_PRINT("pid%d: entering handle\n", client->pid);
    ssize_t len;
    do {
        len =
            read(client->fd, (client->buf + client->buflen), sizeof(client->buf) - client->buflen);
    } while (len < 0 && errno == EINTR);

    if (len < 0) {
        if (!(errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct json_object *e = json_object_new_object();
            json_object_object_add(e, "phase", json_object_new_string("read"));
            json_object_object_add(e, "error", json_object_new_string(strerror(errno)));
            qmeventd_log_event(
                client_vmid(client), client_qemu_pid(client), client->pid, QLOG_ERROR,
                "qmeventd", "IPC_ERROR", e
            );
            json_object_put(e);
            cleanup_client(client);
        }
        return;
    } else if (len == 0) {
        VERBOSE_PRINT("pid%d: got EOF\n", client->pid);
        cleanup_client(client);
        return;
    }

    VERBOSE_PRINT("pid%d: read %ld bytes\n", client->pid, len);
    client->buflen += len;

    struct json_tokener *tok = json_tokener_new();
    struct json_object *jobj = NULL;
    enum json_tokener_error jerr = json_tokener_success;
    while (jerr == json_tokener_success && client->buflen != 0) {
        jobj = json_tokener_parse_ex(tok, client->buf, (int)client->buflen);
        jerr = json_tokener_get_error(tok);
        unsigned int offset = (unsigned int)tok->char_offset;
        switch (jerr) {
        case json_tokener_success:
            // move rest from buffer to front
            memmove(client->buf, client->buf + offset, client->buflen - offset);
            client->buflen -= offset;
            if (json_object_is_type(jobj, json_type_object)) {
                struct json_object *obj;
                if (json_object_object_get_ex(jobj, "QMP", &obj)) {
                    handle_qmp_handshake(client);
                } else if (json_object_object_get_ex(jobj, "event", &obj)) {
                    handle_qmp_event(client, jobj);
                } else if (json_object_object_get_ex(jobj, "return", &obj)) {
                    handle_qmp_return(client, obj, false);
                } else if (json_object_object_get_ex(jobj, "error", &obj)) {
                    handle_qmp_return(client, obj, true);
                } else if (json_object_object_get_ex(jobj, "vzdump", &obj)) {
                    handle_vzdump_handshake(client, obj);
                } // else ignore message
            }
            break;
        case json_tokener_continue:
            if (client->buflen >= sizeof(client->buf)) {
                log_protocol_error(
                    client, protocol_error_source(client), "message too large", NULL
                );
                memset(client->buf, 0, sizeof(client->buf));
                client->buflen = 0;
            } // else we have enough space try again after next read
            break;
        default:
            {
                char detail[32];
                snprintf(detail, sizeof(detail), "tokener error %d", (int)jerr);
                log_protocol_error(
                    client, protocol_error_source(client), "malformed JSON message", detail
                );
            }
            memset(client->buf, 0, client->buflen);
            client->buflen = 0;
            break;
        }
        json_object_put(jobj);
    }
    json_tokener_free(tok);
}

static void sigkill(void *ptr, void *time_ptr) {
    struct Client *data = ptr;
    int err;

    if (data->timeout != 0 && data->timeout > *(time_t *)time_ptr) {
        return;
    }

    if (data->pidfd > 0) {
        err = pidfd_send_signal(data->pidfd, SIGKILL, NULL, 0);
        (void)close(data->pidfd);
        data->pidfd = -1;
    } else {
        err = kill(data->pid, SIGKILL);
    }

    if (err < 0) {
        if (errno != ESRCH) {
            struct json_object *e = json_object_new_object();
            json_object_object_add(e, "pid", json_object_new_int((int)data->pid));
            json_object_object_add(e, "signal", json_object_new_string("SIGKILL"));
            json_object_object_add(e, "error", json_object_new_string(strerror(errno)));
            qmeventd_log_event(
                data->qemu.vmid[0] ? data->qemu.vmid : NULL, data->pid, data->pid, QLOG_ERROR,
                "qmeventd", "SIGKILL_FALLBACK", e
            );
            json_object_put(e);
        }
    } else {
        struct json_object *p = json_object_new_object();
        json_object_object_add(p, "pid", json_object_new_int((int)data->pid));
        json_object_object_add(p, "signal", json_object_new_string("SIGKILL"));
        qmeventd_log_event(
            data->qemu.vmid[0] ? data->qemu.vmid : NULL, data->pid, data->pid, QLOG_WARNING,
            "qmeventd", "SIGKILL_FALLBACK", p
        );
        json_object_put(p);
    }

    data->timeout = 0;

    // remove ourselves from the list
    forced_cleanups = g_slist_remove(forced_cleanups, ptr);
}

static void handle_forced_cleanup() {
    if (g_slist_length(forced_cleanups) > 0) {
        VERBOSE_PRINT("clearing forced cleanup backlog\n");
        time_t cur_time = time(NULL);
        g_slist_foreach(forced_cleanups, sigkill, &cur_time);
    }
    needs_cleanup = g_slist_length(forced_cleanups) > 0;
}

/*
 * Timeout for the main epoll_wait(). A forced-cleanup deadline keeps the
 * original 10 s granularity; a pending log backlog only *shortens* that wait
 * so a recovered journal is drained promptly. It never changes a kill or
 * cleanup deadline itself.
 */
static int daemon_wait_timeout_ms(void) {
    int timeout_ms = -1;

    if (needs_cleanup) {
        timeout_ms = 10 * 1000;
    }
    if (qmeventd_log_has_pending() && (timeout_ms < 0 || timeout_ms > 200)) {
        timeout_ms = 200;
    }
    /* the capture worker also needs a bounded tick (supervision/backoff); this
     * only *shortens* the wait and never delays a kill/cleanup deadline */
    if (capture_mod) {
        int cap = qmev_capture_wait_timeout_ms(capture_mod);
        if (cap >= 0 && (timeout_ms < 0 || cap < timeout_ms)) {
            timeout_ms = cap;
        }
    }
    return timeout_ms;
}

/*
 * The daemon's own listen token. The capture worker's fds are registered and
 * torn down by the capture module itself (qmev_capture_epoll_sync), which owns
 * private dup()s of its volatile fds so a reused fd number can never be
 * mis-DELeted or skipped.
 */
static int listen_token;

int main(int argc, char *argv[]) {
    int opt;
    int daemonize = 1;
    char *socket_path = NULL;
    progname = argv[0];

    /* key-event records go to the daemon's stdout, which systemd wires to the
     * journal; delivery is non-blocking and never stalls the control loop */
    qmeventd_log_init(STDOUT_FILENO);

    while ((opt = getopt(argc, argv, "hfvt:")) != -1) {
        switch (opt) {
        case 'f':
            daemonize = 0;
            break;
        case 'v':
            verbose = 1;
            break;
        case 't':
            errno = 0;
            char *endptr = NULL;
            kill_timeout = strtoul(optarg, &endptr, 10);
            if (errno != 0 || *endptr != '\0' || kill_timeout == 0) {
                usage();
                exit(EXIT_FAILURE);
            }
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
            break;
        default:
            usage();
            exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        usage();
        exit(EXIT_FAILURE);
    }

    signal(SIGCHLD, SIG_IGN);

    socket_path = argv[optind];

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    bail_neg(sock, "socket");

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    unlink(socket_path);
    bail_neg(bind(sock, (struct sockaddr *)&addr, sizeof(addr)), "bind");

    struct epoll_event ev, events[8];
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    bail_neg(epoll_fd, "epoll_create1");

    ev.events = EPOLLIN;
    ev.data.ptr = &listen_token;
    bail_neg(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev), "epoll_ctl");

    bail_neg(listen(sock, 10), "listen");

    if (daemonize) {
        bail_neg(daemon(0, 1), "daemon");
    }

    vm_clients = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);

    /* The capture bridge is created here but spawns its worker lazily on the
     * first observation, and never interferes with the QMP control path. */
    capture_mod = qmev_capture_new(NULL);

    int nevents;
    void *cap_io_tok = qmev_capture_io_token();
    void *cap_pidfd_tok = qmev_capture_pidfd_token();

    for (;;) {
        int timeout_ms;
        if (capture_mod) {
            qmev_capture_epoll_sync(capture_mod, epoll_fd);
        }
        timeout_ms = daemon_wait_timeout_ms();
        nevents = epoll_wait(epoll_fd, events, 8, timeout_ms);
        if (nevents < 0 && errno == EINTR) {
            continue;
        }
        bail_neg(nevents, "epoll_wait");

        for (int n = 0; n < nevents; n++) {
            if (events[n].data.ptr == &listen_token) {

                int conn_sock = accept4(sock, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                log_neg(conn_sock, "accept");
                if (conn_sock > -1) {
                    add_new_client(conn_sock);
                }
            } else if (events[n].data.ptr == cap_io_tok) {
                qmev_capture_handle_readable(capture_mod);
            } else if (events[n].data.ptr == cap_pidfd_tok) {
                qmev_capture_tick(capture_mod);
            } else {
                handle_client((struct Client *)events[n].data.ptr);
            }
        }
        /* flush any log backlog (also on an idle timeout) and report drops */
        qmeventd_log_flush_pending();
        /* bounded capture-worker supervision: liveness, backoff, state replay */
        if (capture_mod) {
            qmev_capture_tick(capture_mod);
        }
        handle_forced_cleanup();
    }
}
