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

    On top of that qmeventd is the event layer for the whole VM life cycle:
    it collects QMP events, injected operation events (snapshot, backup,
    migration, ...) and the result of its own guest agent monitoring, keeps a
    per-VM state (qmeventd-monitor.c), derives composite events (crash, hang,
    boot failure, ...) and exposes every event by
      - a journal record,
      - a JSON line to every subscriber of the socket,
      - running `qm event <vmid> <EVENT> <json>` for VMs that have a
        hookscript or vmhook configured.
    The current state of all VMs can be queried on the same socket.
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
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "qmeventd-log.h"
#include "qmeventd.h"

#define DEFAULT_KILL_TIMEOUT 60
#define DEFAULT_QM_PATH "/usr/sbin/qm"
#define DEFAULT_RUN_DIR "/var/run/qemu-server"

// a subscriber that cannot keep up is disconnected
#define SUBSCRIBER_OUT_MAX (1024 * 1024)
// at most this many events per VM and window are queued for `qm event`
#define DISPATCH_BUDGET 30
#define DISPATCH_WINDOW_MS (10 * 1000ULL)
#define DISPATCH_QUEUE_MAX 64
// a `qm event` run (hookscript, vmhook) taking longer is killed
#define DISPATCH_TIMEOUT_MS (15 * 60 * 1000ULL)
// a tagged QMP request of the monitor without answer is given up
#define QMP_REQUEST_TIMEOUT_MS (10 * 1000ULL)
// at most this many events per VM and window reach journal and subscribers
#define EVENT_BUDGET 100
#define EVENT_WINDOW_MS (10 * 1000ULL)

static int verbose = 0;
static int kill_timeout = DEFAULT_KILL_TIMEOUT;
static int epoll_fd = 0;
static const char *progname;
GHashTable *vm_clients; // key=vmid (freed on remove), value=*Client (free manually)
GSList *forced_cleanups;
static int needs_cleanup = 0;

static const char *qm_path = DEFAULT_QM_PATH;
static const char *run_dir = DEFAULT_RUN_DIR;
static EpollKind listen_tag = EP_LISTEN;
static EpollKind timer_tag = EP_TIMER;
static GSList *subscribers; // *Client of type CLIENT_SUBSCRIBER
static GHashTable *dispatch_queues; // vmid -> *DispatchQueue
static unsigned long long event_seq = 0;
static unsigned long long self_starttime = 0;

/*
 * Helper functions
 */

static void usage() {
    fprintf(stderr, "Usage: %s [-f] [-v] PATH\n", progname);
    fprintf(stderr, "  -f       run in foreground (default: false)\n");
    fprintf(stderr, "  -v       verbose (default: false)\n");
    fprintf(stderr, "  -t <s>   kill timeout (default: %ds)\n", DEFAULT_KILL_TIMEOUT);
    fprintf(stderr, "  -q <cmd> qm command (default: %s)\n", DEFAULT_QM_PATH);
    fprintf(stderr, "  -r <dir> runtime directory of the VMs (default: %s)\n", DEFAULT_RUN_DIR);
    fprintf(stderr, "  PATH     use PATH for socket\n");
}

static pid_t get_peer_from_fd(int fd, uid_t *uid) {
    struct ucred credentials = {.pid = 0, .uid = (uid_t)-1, .gid = 0};
    socklen_t len = sizeof(struct ucred);
    log_neg(getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &len), "getsockopt");
    *uid = credentials.uid;
    return credentials.pid;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

// process start time in clock ticks since boot, 0 on error
static unsigned long long get_starttime(pid_t pid) {
    char path[64], buf[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *fp = fopen(path, "re");
    if (!fp) {
        return 0;
    }
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';

    // the command name may contain spaces, fields count from the last ')'
    char *p = strrchr(buf, ')');
    if (!p) {
        return 0;
    }
    p++;
    // p points to the space before field 3 (state), starttime is field 22
    for (int field = 3; field < 22 && p; field++) {
        p = strchr(p + 1, ' ');
    }
    return p ? strtoull(p + 1, NULL, 10) : 0;
}

static bool vmid_valid(const char *vmid) {
    if (!vmid || !*vmid || strlen(vmid) > 9) {
        return false;
    }
    for (const char *c = vmid; *c; c++) {
        if (*c < '0' || *c > '9') {
            return false;
        }
    }
    return vmid[0] != '0';
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
 * output to subscriber and control clients
 */

static void arm_output(struct Client *client, bool on) {
    if (client->out_armed == on) {
        return;
    }
    struct epoll_event ev;
    ev.events = EPOLLIN | (on ? EPOLLOUT : 0);
    ev.data.ptr = client;
    log_neg(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev), "epoll_ctl mod");
    client->out_armed = on;
}

// returns false if the client could not take the data and must be removed
static bool flush_output(struct Client *client) {
    while (client->out && client->out->len > 0) {
        ssize_t n = send(client->fd, client->out->str, client->out->len, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                arm_output(client, true);
                return true;
            }
            return false;
        }
        g_string_erase(client->out, 0, n);
    }
    arm_output(client, false);
    return true;
}

static void queue_output(struct Client *client, const char *data, size_t len) {
    if (client->dead) {
        return;
    }
    if (!client->out) {
        client->out = g_string_new(NULL);
    }
    if (client->out->len + len > SUBSCRIBER_OUT_MAX) {
        fprintf(stderr, "pid%d: event subscriber too slow, disconnecting\n", client->pid);
        client->dead = true;
        return;
    }
    g_string_append_len(client->out, data, len);
    if (!flush_output(client)) {
        client->dead = true;
    }
}

static void queue_json(struct Client *client, struct json_object *obj) {
    const char *str = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
    queue_output(client, str, strlen(str));
    queue_output(client, "\n", 1);
}

/*
 * event pipeline
 */

typedef enum {
    EV_LOG = 1,      // journal record
    EV_DISPATCH = 2, // run `qm event` (if the VM wants it)
    EV_NOISY = 4,    // may repeat at high rate: subject to the storm limit
} EventFlags;

struct event_info {
    const char *name;
    QLogLevel level;
    int flags;
};

static const struct event_info event_table[] = {
    // QMP events
    {"SHUTDOWN", QLOG_INFO, EV_LOG | EV_DISPATCH},
    {"POWERDOWN", QLOG_INFO, EV_LOG | EV_DISPATCH},
    {"RESET", QLOG_INFO, EV_LOG | EV_DISPATCH},
    {"STOP", QLOG_INFO, EV_LOG | EV_DISPATCH | EV_NOISY},
    {"RESUME", QLOG_INFO, EV_LOG | EV_DISPATCH | EV_NOISY},
    {"SUSPEND", QLOG_INFO, EV_LOG | EV_DISPATCH | EV_NOISY},
    {"SUSPEND_DISK", QLOG_INFO, EV_LOG | EV_DISPATCH},
    {"WAKEUP", QLOG_INFO, EV_LOG | EV_DISPATCH | EV_NOISY},
    {"GUEST_PANICKED", QLOG_ERROR, EV_LOG | EV_DISPATCH},
    {"GUEST_CRASHLOADED", QLOG_ERROR, EV_LOG | EV_DISPATCH},
    {"WATCHDOG", QLOG_WARNING, EV_LOG | EV_DISPATCH | EV_NOISY},
    {"BLOCK_IO_ERROR", QLOG_ERROR, EV_LOG | EV_DISPATCH | EV_NOISY},
    {"VSERPORT_CHANGE", QLOG_INFO, EV_LOG | EV_NOISY},
    // qmeventd
    {"STARTED", QLOG_INFO, EV_LOG | EV_DISPATCH},
    {"EXITED", QLOG_INFO, EV_LOG | EV_DISPATCH},
    // agent monitor
    {"AGENT_UP", QLOG_INFO, EV_LOG | EV_DISPATCH},
    {"AGENT_LOST", QLOG_WARNING, EV_LOG | EV_DISPATCH},
    {"AGENT_RECOVERED", QLOG_INFO, EV_LOG | EV_DISPATCH},
    {"AGENT_NO_RESPONSE", QLOG_WARNING, EV_LOG | EV_DISPATCH},
    // composite
    {"GUEST_CRASH", QLOG_ERROR, EV_LOG | EV_DISPATCH},
    {"GUEST_HANG", QLOG_ERROR, EV_LOG | EV_DISPATCH},
    {"AGENT_FAULT", QLOG_WARNING, EV_LOG | EV_DISPATCH},
    {"BOOT_FAILED", QLOG_ERROR, EV_LOG | EV_DISPATCH},
    {"REBOOT_LOOP", QLOG_ERROR, EV_LOG | EV_DISPATCH},
    {"STORAGE_FAULT", QLOG_ERROR, EV_LOG | EV_DISPATCH},
    // injected operation events, their hooks already ran in the API task
    {"PRE_SNAPSHOT", QLOG_INFO, EV_LOG},
    {"POST_SNAPSHOT", QLOG_INFO, EV_LOG},
    {"SNAPSHOT_FAILED", QLOG_WARNING, EV_LOG},
    {"PRE_SNAPSHOT_DELETE", QLOG_INFO, EV_LOG},
    {"POST_SNAPSHOT_DELETE", QLOG_INFO, EV_LOG},
    {"SNAPSHOT_DELETE_FAILED", QLOG_WARNING, EV_LOG},
    {"PRE_ROLLBACK", QLOG_INFO, EV_LOG},
    {"POST_ROLLBACK", QLOG_INFO, EV_LOG},
    {"ROLLBACK_FAILED", QLOG_WARNING, EV_LOG},
    {"PRE_BACKUP", QLOG_INFO, EV_LOG},
    {"POST_BACKUP", QLOG_INFO, EV_LOG},
    {"BACKUP_FAILED", QLOG_WARNING, EV_LOG},
    {"PRE_MIGRATE", QLOG_INFO, EV_LOG},
    {"POST_MIGRATE", QLOG_INFO, EV_LOG},
    {"MIGRATE_FAILED", QLOG_WARNING, EV_LOG},
    {"MIGRATE_IN", QLOG_INFO, EV_LOG},
    {"PRE_CLONE", QLOG_INFO, EV_LOG},
    {"POST_CLONE", QLOG_INFO, EV_LOG},
    {"POST_RESTORE", QLOG_INFO, EV_LOG},
    {"PRE_DESTROY", QLOG_INFO, EV_LOG},
    {"PRE_RECOVERY", QLOG_WARNING, EV_LOG},
    {"POST_RECOVERY", QLOG_WARNING, EV_LOG},
};

static const struct event_info *lookup_event(const char *name) {
    if (!name) {
        return NULL;
    }
    for (size_t i = 0; i < sizeof(event_table) / sizeof(event_table[0]); i++) {
        if (!strcmp(name, event_table[i].name)) {
            return &event_table[i];
        }
    }
    return NULL;
}

static bool is_injectable(const struct event_info *info) {
    return info && !(info->flags & EV_DISPATCH) && strcmp(info->name, "VSERPORT_CHANGE");
}

struct DispatchItem {
    char *event;
    char *json;
};

static void dispatch_item_free(gpointer ptr) {
    struct DispatchItem *item = ptr;
    free(item->event);
    free(item->json);
    free(item);
}

static void dispatch_start_next(struct DispatchQueue *q);

static void dispatch_queue_free(gpointer ptr) {
    struct DispatchQueue *q = ptr;
    g_queue_free_full(q->pending, dispatch_item_free);
    free(q);
}

static void dispatch_child_done(struct DispatchQueue *q) {
    if (q->pidfd >= 0) {
        log_neg(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, q->pidfd, NULL), "epoll del dispatch");
        (void)close(q->pidfd);
        q->pidfd = -1;
    }
    q->child = 0;
    dispatch_start_next(q);
}

static void dispatch_start_next(struct DispatchQueue *q) {
    while (!q->child) {
        struct DispatchItem *item = g_queue_pop_head(q->pending);
        if (!item) {
            // idle and empty: forget the VM (removing frees q)
            g_hash_table_remove(dispatch_queues, q->vmid);
            return;
        }

        // the child waits on `gate` until we hold its pidfd: it cannot exit
        // (and its pid be reused) before that
        int gate[2];
        if (pipe2(gate, O_CLOEXEC) < 0) {
            perror("pipe2");
            dispatch_item_free(item);
            continue;
        }

        int pid = fork();
        if (pid < 0) {
            fprintf(stderr, "%s: fork for event %s failed: %s\n", q->vmid, item->event, strerror(errno));
            (void)close(gate[0]);
            (void)close(gate[1]);
            dispatch_item_free(item);
            continue;
        }
        if (pid == 0) {
            char c;
            (void)close(gate[1]);
            while (read(gate[0], &c, 1) < 0 && errno == EINTR) {
            }
            char *args[] = {(char *)qm_path, "event", q->vmid, item->event, item->json, NULL};
            execvp(qm_path, args);
            perror("execvp");
            _exit(1);
        }
        dispatch_item_free(item);
        (void)close(gate[0]);

        // wait for the child before starting the next event of this VM
        int pidfd = pidfd_open(pid, 0);
        (void)close(gate[1]); // releases the child
        if (pidfd < 0) {
            // no pidfd support: no ordering, but keep going
            continue;
        }
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.ptr = q;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pidfd, &ev) < 0) {
            perror("epoll_ctl dispatch add");
            (void)close(pidfd);
            continue;
        }
        q->child = pid;
        q->pidfd = pidfd;
        q->deadline = now_ms() + DISPATCH_TIMEOUT_MS;
    }
}

static void dispatch_log(const char *vmid, const char *what, const char *event) {
    struct json_object *d = json_object_new_object();
    json_object_object_add(d, "event", json_object_new_string(event));
    json_object_object_add(d, "reason", json_object_new_string(what));
    qmeventd_log_event(vmid, 0, QLOG_WARNING, "qmeventd", "DISPATCH_DROPPED", d);
    json_object_put(d);
}

// noisy events are limited per window and dropped first, all others are
// always queued so a storm cannot swallow e.g. SHUTDOWN or GUEST_CRASH
static void dispatch_event(const char *vmid, const char *event, const char *json, bool noisy) {
    struct DispatchQueue *q = g_hash_table_lookup(dispatch_queues, vmid);
    if (!q) {
        q = calloc(1, sizeof(*q));
        if (!q) {
            return;
        }
        q->ep_kind = EP_DISPATCH;
        snprintf(q->vmid, sizeof(q->vmid), "%s", vmid);
        q->pending = g_queue_new();
        q->pidfd = -1;
        g_hash_table_insert(dispatch_queues, q->vmid, q);
    }

    uint64_t now = now_ms();
    if (now - q->window_start > DISPATCH_WINDOW_MS) {
        q->window_start = now;
        q->window_count = 0;
        q->overflow_logged = false;
    }
    bool over = noisy && (++q->window_count > DISPATCH_BUDGET ||
                          g_queue_get_length(q->pending) >= DISPATCH_QUEUE_MAX);
    if (over) {
        if (!q->overflow_logged) {
            dispatch_log(vmid, "too many events", event);
            q->overflow_logged = true;
        }
        if (!q->child && g_queue_is_empty(q->pending)) {
            g_hash_table_remove(dispatch_queues, q->vmid);
        }
        return;
    }

    struct DispatchItem *item = calloc(1, sizeof(*item));
    if (!item || !(item->event = strdup(event)) || !(item->json = strdup(json))) {
        if (item) {
            dispatch_item_free(item);
        }
        return;
    }
    g_queue_push_tail(q->pending, item);
    if (!q->child) {
        dispatch_start_next(q);
    }
}

static void handle_dispatch(struct DispatchQueue *q) {
    // pidfd readable: the child exited (SIGCHLD is ignored, so it is reaped)
    dispatch_child_done(q);
}

// kill `qm event` runs that hang (e.g. a stuck hookscript)
static void dispatch_check_timeouts(uint64_t now) {
    GList *queues = g_hash_table_get_values(dispatch_queues);
    for (GList *l = queues; l; l = l->next) {
        struct DispatchQueue *q = l->data;
        if (q->child && q->pidfd >= 0 && now >= q->deadline) {
            dispatch_log(q->vmid, "qm event timed out, killed", "-");
            log_neg(pidfd_send_signal(q->pidfd, SIGKILL, NULL, 0), "kill qm event");
            q->deadline = UINT64_MAX; // wait for the exit
        }
    }
    g_list_free(queues);
}

static void broadcast_line(const char *json, size_t len);
static bool event_budget(struct Client *vm);
static void report_suppressed(struct Client *vm);

/*
 * Single entry point for every event. `vm` is the QEMU client of the VM if it
 * is running here (may be NULL for injected events of stopped VMs). `data` is
 * borrowed.
 */
static void emit_event(
    struct Client *vm,
    const char *vmid,
    const char *source,
    const char *event,
    struct json_object *data
) {
    const struct event_info *info = lookup_event(event);
    if (!info) {
        return;
    }

    pid_t pid = vm ? vm->pid : 0;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    if (vm) {
        snprintf(vm->qemu.mon.last_event, sizeof(vm->qemu.mon.last_event), "%s", event);
        vm->qemu.mon.last_event_ts = (uint64_t)ts.tv_sec;
    }

    struct json_object *ev = json_object_new_object();
    json_object_object_add(ev, "vmid", json_object_new_string(vmid));
    json_object_object_add(ev, "pid", json_object_new_int(pid));
    json_object_object_add(ev, "event", json_object_new_string(event));
    json_object_object_add(ev, "source", json_object_new_string(source));
    json_object_object_add(ev, "time", json_object_new_int64((int64_t)ts.tv_sec));
    json_object_object_add(ev, "seq", json_object_new_int64((int64_t)++event_seq));
    if (data) {
        json_object_object_add(ev, "data", json_object_get(data));
    }
    if (vm) {
        json_object_object_add(ev, "state", mon_state_json(&vm->qemu.mon));
    }

    const char *json = json_object_to_json_string_ext(ev, JSON_C_TO_STRING_PLAIN);

    // a storming guest (e.g. BLOCK_IO_ERROR on every request) must not flood
    // the journal; life cycle, crash and operation events always pass
    if (!vm || !(info->flags & EV_NOISY) || event_budget(vm)) {
        if (info->flags & EV_LOG) {
            qmeventd_log_event(vmid, pid, info->level, source, event, ev);
        }
        broadcast_line(json, strlen(json));
    }

    // STARTED is always dispatched: `qm event` answers with the configuration
    if (vm && (info->flags & EV_DISPATCH) && (vm->qemu.mon.dispatch || !strcmp(event, "STARTED"))) {
        dispatch_event(vmid, event, json, info->flags & EV_NOISY);
    }

    json_object_put(ev);
}

static void broadcast_line(const char *json, size_t len) {
    GSList *dead = NULL;
    for (GSList *l = subscribers; l; l = l->next) {
        struct Client *sub = l->data;
        queue_output(sub, json, len);
        queue_output(sub, "\n", 1);
        if (sub->dead) {
            dead = g_slist_prepend(dead, sub);
        }
    }
    for (GSList *l = dead; l; l = l->next) {
        cleanup_client(l->data);
    }
    g_slist_free(dead);
}

// report events dropped by the storm limit of a VM
static void report_suppressed(struct Client *vm) {
    if (!vm->qemu.ev_suppressed) {
        return;
    }
    struct json_object *ev = json_object_new_object();
    struct json_object *d = json_object_new_object();
    json_object_object_add(d, "suppressed", json_object_new_int64((int64_t)vm->qemu.ev_suppressed));
    json_object_object_add(ev, "vmid", json_object_new_string(vm->qemu.vmid));
    json_object_object_add(ev, "pid", json_object_new_int(vm->pid));
    json_object_object_add(ev, "event", json_object_new_string("EVENTS_SUPPRESSED"));
    json_object_object_add(ev, "source", json_object_new_string("qmeventd"));
    json_object_object_add(ev, "time", json_object_new_int64((int64_t)time(NULL)));
    json_object_object_add(ev, "seq", json_object_new_int64((int64_t)++event_seq));
    json_object_object_add(ev, "data", d);
    qmeventd_log_event(vm->qemu.vmid, vm->pid, QLOG_WARNING, "qmeventd", "EVENTS_SUPPRESSED", ev);
    const char *json = json_object_to_json_string_ext(ev, JSON_C_TO_STRING_PLAIN);
    broadcast_line(json, strlen(json));
    json_object_put(ev);
    vm->qemu.ev_suppressed = 0;
}

// true if the event of this VM may go to journal and subscribers
static bool event_budget(struct Client *vm) {
    uint64_t now = now_ms();
    if (now - vm->qemu.ev_window_start > EVENT_WINDOW_MS) {
        report_suppressed(vm);
        vm->qemu.ev_window_start = now;
        vm->qemu.ev_count = 0;
    }
    if (++vm->qemu.ev_count > EVENT_BUDGET) {
        vm->qemu.ev_suppressed++;
        return false;
    }
    return true;
}

static const char *monitor_source(const char *event) {
    return strncmp(event, "AGENT_", 6) || !strcmp(event, "AGENT_FAULT") ? "derived" : "monitor";
}

// mon_emit_fn for the monitor state machine
static void monitor_emit(void *ctx, const char *event, struct json_object *data) {
    struct Client *vm = ctx;
    emit_event(vm, vm->qemu.vmid, monitor_source(event), event, data);
    json_object_put(data);
}

/*
 * qmp handling functions
 */

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
        fprintf(stderr, "could not get vmid from pid %d\n", client->pid);
        client->qemu.vmid[0] = '\0';
        // removed by handle_client once the current message is processed
        client->dead = true;
        return;
    }

    VERBOSE_PRINT("pid%d: assigned VMID: %s\n", client->pid, client->qemu.vmid);
    client->type = CLIENT_QEMU;
    mon_init(&client->qemu.mon, now_ms());
    // QEMU reconnects after a qmeventd restart, this is no new VM start
    unsigned long long starttime = get_starttime(client->pid);
    client->qemu.reconnect = starttime && self_starttime && starttime < self_starttime;
    if (!g_hash_table_insert(vm_clients, strdup(client->qemu.vmid), client)) {
        // not fatal, just means backup handling won't work
        fprintf(stderr, "%s: could not insert client into VMID->client table\n", client->qemu.vmid);
    }

    static const char qmp_answer[] = "{\"execute\":\"qmp_capabilities\"}\n";
    send_qmp_cmd(client, qmp_answer, sizeof(qmp_answer));
}

void handle_qmp_event(struct Client *client, struct json_object *obj) {
    struct json_object *event;
    if (!json_object_object_get_ex(obj, "event", &event)) {
        return;
    }
    const char *event_name = json_object_get_string(event);
    VERBOSE_PRINT("%s: got QMP event: %s\n", client->qemu.vmid, event_name);

    if (client->type == CLIENT_QEMU) {
        struct json_object *data = NULL;
        json_object_object_get_ex(obj, "data", &data);
        emit_event(client, client->qemu.vmid, "qmp", event_name, data);
        mon_on_qmp_event(&client->qemu.mon, now_ms(), event_name, data, monitor_emit, client);
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
        const char *msg = "n/a";
        struct json_object *desc;
        if (json_object_object_get_ex(data, "desc", &desc)) {
            msg = json_object_get_string(desc);
        }
        fprintf(stderr, "%s: received error from QMP: %s\n", client->qemu.vmid, msg);
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
        if (active) {
            VERBOSE_PRINT("%s: got status: VM is active\n", client->qemu.vmid);
        } else if (!client->qemu.backup) {
            terminate_client(client);
        } else {
            // if we're in a backup, don't do anything, vzdump will notify
            // us when the backup finishes
            VERBOSE_PRINT("%s: not active, but running backup - keep alive\n", client->qemu.vmid);
        }
        break;

    // this means we received the empty return from our handshake answer
    case STATE_HANDSHAKE:
        client->state = STATE_IDLE;
        VERBOSE_PRINT("%s: QMP handshake complete\n", client->qemu.vmid);
        if (client->type == CLIENT_QEMU) {
            static const char init_req[] = "{\"execute\":\"query-status\",\"id\":\"qmev-init\"}\n";
            struct json_object *d = json_object_new_object();
            json_object_object_add(d, "reconnect", json_object_new_boolean(client->qemu.reconnect));
            emit_event(client, client->qemu.vmid, "qmeventd", "STARTED", d);
            json_object_put(d);
            send_qmp_cmd(client, init_req, sizeof(init_req));
        }
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
 * requests of the monitor on the QMP connection, tagged with an "id" so they
 * never interfere with the shutdown handling above
 */

static bool qmp_ready(struct Client *client) {
    return client->type == CLIENT_QEMU && client->state != STATE_HANDSHAKE &&
           client->state != STATE_TERMINATING;
}

static void probe_finish(struct Client *vm, MonProbeResult res) {
    struct Probe *probe = vm->qemu.probe;
    if (probe) {
        log_neg(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, probe->fd, NULL), "epoll del probe");
        (void)close(probe->fd);
        free(probe);
        vm->qemu.probe = NULL;
    }
    mon_probe_result(&vm->qemu.mon, now_ms(), res, monitor_emit, vm);
}

// connect to the guest agent socket and send guest-sync-delimited + guest-ping
static void probe_start(struct Client *vm) {
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    int len = snprintf(path, sizeof(path), "%s/%s.qga", run_dir, vm->qemu.vmid);
    if (len < 0 || (size_t)len >= sizeof(path)) {
        mon_probe_result(&vm->qemu.mon, now_ms(), PROBE_BUSY, monitor_emit, vm);
        return;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("probe socket");
        mon_probe_result(&vm->qemu.mon, now_ms(), PROBE_BUSY, monitor_emit, vm);
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, (size_t)len);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        // EAGAIN: backlog full, somebody else talks to the agent
        MonProbeResult res = (errno == EAGAIN || errno == EINPROGRESS) ? PROBE_BUSY : PROBE_FAIL;
        if (res == PROBE_FAIL) {
            VERBOSE_PRINT("%s: agent probe connect failed: %s\n", vm->qemu.vmid, strerror(errno));
        }
        (void)close(fd);
        mon_probe_result(&vm->qemu.mon, now_ms(), res, monitor_emit, vm);
        return;
    }

    // Always id 1: PVE::QMPClient skips answers with an id lower than its own
    // (<pid>0<n>), so a late answer to a timed out probe cannot confuse it
    char req[256];
    unsigned id = 1;
    int reqlen = snprintf(
        req, sizeof(req),
        "{\"execute\":\"guest-sync-delimited\",\"arguments\":{\"id\":%u}}\n"
        "{\"execute\":\"guest-ping\"}\n",
        id
    );
    if (!must_write(fd, req, (size_t)reqlen)) {
        (void)close(fd);
        mon_probe_result(&vm->qemu.mon, now_ms(), PROBE_FAIL, monitor_emit, vm);
        return;
    }

    struct Probe *probe = calloc(1, sizeof(*probe));
    if (!probe) {
        (void)close(fd);
        mon_probe_result(&vm->qemu.mon, now_ms(), PROBE_BUSY, monitor_emit, vm);
        return;
    }
    probe->ep_kind = EP_PROBE;
    probe->vm = vm;
    probe->fd = fd;
    probe->deadline = now_ms() + (uint64_t)vm->qemu.mon.hb.timeout * 1000ULL;

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = probe;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        perror("epoll_ctl probe add");
        (void)close(fd);
        free(probe);
        mon_probe_result(&vm->qemu.mon, now_ms(), PROBE_BUSY, monitor_emit, vm);
        return;
    }
    vm->qemu.probe = probe;
}

// the agent answers 0xff, {"return": id} and then the guest-ping result
static void handle_probe(struct Probe *probe) {
    struct Client *vm = probe->vm;
    ssize_t n;
    do {
        n = read(probe->fd, probe->buf + probe->len, sizeof(probe->buf) - 1 - probe->len);
    } while (n < 0 && errno == EINTR);

    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return;
    }
    if (n <= 0) {
        probe_finish(vm, PROBE_FAIL);
        return;
    }
    probe->len += (size_t)n;
    probe->buf[probe->len] = '\0';

    char *start = memchr(probe->buf, 0xff, probe->len);
    if (start) {
        // count complete answers after the delimiter
        struct json_tokener *tok = json_tokener_new();
        const char *p = start + 1;
        const char *end = probe->buf + probe->len;
        int answers = 0;
        while (p < end) {
            while (p < end && (*p == '\n' || *p == '\r' || *p == ' ')) {
                p++;
            }
            if (p >= end) {
                break;
            }
            json_tokener_reset(tok);
            struct json_object *o = json_tokener_parse_ex(tok, p, (int)(end - p));
            if (!o) {
                break;
            }
            if (json_object_object_get_ex(o, "return", NULL) ||
                json_object_object_get_ex(o, "error", NULL)) {
                answers++;
            }
            json_object_put(o);
            p += tok->char_offset;
        }
        json_tokener_free(tok);
        if (answers >= 2) {
            probe_finish(vm, PROBE_OK);
            return;
        }
    }

    if (probe->len >= sizeof(probe->buf) - 1) {
        probe_finish(vm, PROBE_FAIL);
    }
}

static void request_io_sample(struct Client *vm) {
    static const char req[] = "{\"execute\":\"query-blockstats\",\"id\":\"qmev-io\"}\n";
    if (!qmp_ready(vm)) {
        mon_io_sample(&vm->qemu.mon, now_ms(), false, 0, monitor_emit, vm);
        return;
    }
    vm->qemu.req_blockstats = true;
    vm->qemu.req_blockstats_since = now_ms();
    send_qmp_cmd(vm, req, sizeof(req));
}

// before probing, make sure nobody else (e.g. a backup freeze) uses the agent
static void request_probe(struct Client *vm) {
    static const char req[] = "{\"execute\":\"query-chardev\",\"id\":\"qmev-chardev\"}\n";
    mon_probe_started(&vm->qemu.mon);
    vm->qemu.req_chardev = true;
    vm->qemu.req_chardev_since = now_ms();
    send_qmp_cmd(vm, req, sizeof(req));
}

static void handle_chardev_return(struct Client *vm, struct json_object *data, bool error) {
    MonProbeResult res = PROBE_BUSY;
    if (!vm->qemu.req_chardev) {
        return; // answer after the request was given up
    }
    vm->qemu.req_chardev = false;

    if (!error && json_object_is_type(data, json_type_array)) {
        size_t n = json_object_array_length(data);
        for (size_t i = 0; i < n; i++) {
            struct json_object *dev = json_object_array_get_idx(data, i);
            struct json_object *label, *filename;
            if (!json_object_object_get_ex(dev, "label", &label) ||
                strcmp(json_object_get_string(label), "qga0") ||
                !json_object_object_get_ex(dev, "filename", &filename)) {
                continue;
            }
            // a socket chardev without peer reports "disconnected:..."
            if (!strncmp(json_object_get_string(filename), "disconnected:", 13)) {
                probe_start(vm);
                return;
            }
            break;
        }
    }
    mon_probe_result(&vm->qemu.mon, now_ms(), res, monitor_emit, vm);
}

static uint64_t stat_value(struct json_object *stats, const char *key) {
    struct json_object *v;
    if (!json_object_object_get_ex(stats, key, &v)) {
        return 0;
    }
    return (uint64_t)json_object_get_int64(v);
}

static void handle_blockstats_return(struct Client *vm, struct json_object *data, bool error) {
    if (!vm->qemu.req_blockstats) {
        return; // answer after the request was given up
    }
    vm->qemu.req_blockstats = false;
    if (error || !json_object_is_type(data, json_type_array)) {
        mon_io_sample(&vm->qemu.mon, now_ms(), false, 0, monitor_emit, vm);
        return;
    }
    uint64_t total = 0;
    size_t n = json_object_array_length(data);
    for (size_t i = 0; i < n; i++) {
        struct json_object *stats;
        if (!json_object_object_get_ex(json_object_array_get_idx(data, i), "stats", &stats)) {
            continue;
        }
        total += stat_value(stats, "rd_operations") + stat_value(stats, "wr_operations") +
                 stat_value(stats, "flush_operations");
    }
    mon_io_sample(&vm->qemu.mon, now_ms(), true, total, monitor_emit, vm);
}

// returns true if the message was one of our tagged requests
static bool handle_tagged_return(
    struct Client *client, struct json_object *msg, struct json_object *data, bool error
) {
    struct json_object *id;
    if (!json_object_object_get_ex(msg, "id", &id) || !json_object_is_type(id, json_type_string)) {
        return false;
    }
    const char *tag = json_object_get_string(id);
    if (strncmp(tag, "qmev-", 5)) {
        return false;
    }
    if (client->type != CLIENT_QEMU) {
        return true;
    }

    if (!strcmp(tag, "qmev-init")) {
        struct json_object *status;
        if (!error && json_object_object_get_ex(data, "status", &status)) {
            mon_set_run_status(&client->qemu.mon, now_ms(), json_object_get_string(status));
        }
    } else if (!strcmp(tag, "qmev-chardev")) {
        handle_chardev_return(client, data, error);
    } else if (!strcmp(tag, "qmev-io")) {
        handle_blockstats_return(client, data, error);
    }
    return true;
}

// periodic work of the monitor, called from the 1s timer
static void monitor_tick_vm(struct Client *vm, uint64_t now) {
    struct VmMon *mon = &vm->qemu.mon;

    if (vm->qemu.probe && now >= vm->qemu.probe->deadline) {
        probe_finish(vm, PROBE_FAIL);
    }

    // a lost QMP answer (e.g. a discarded oversized message) must not stall
    // the monitor forever
    if (vm->qemu.req_chardev && now - vm->qemu.req_chardev_since > QMP_REQUEST_TIMEOUT_MS) {
        vm->qemu.req_chardev = false;
        mon_probe_result(mon, now, PROBE_BUSY, monitor_emit, vm);
    }
    if (vm->qemu.req_blockstats && now - vm->qemu.req_blockstats_since > QMP_REQUEST_TIMEOUT_MS) {
        vm->qemu.req_blockstats = false;
        mon_io_sample(mon, now, false, 0, monitor_emit, vm);
    }

    mon_tick(mon, now, monitor_emit, vm);

    // flush the storm summary even if the guest went quiet
    if (vm->qemu.ev_suppressed && now - vm->qemu.ev_window_start > EVENT_WINDOW_MS) {
        report_suppressed(vm);
    }

    if (!qmp_ready(vm)) {
        return;
    }
    if (mon_io_request(mon) != IO_NONE && !vm->qemu.req_blockstats) {
        request_io_sample(vm);
    } else if (mon_probe_due(mon, now, vm->qemu.backup) && !vm->qemu.req_chardev) {
        request_probe(vm);
    }
}

static void handle_timer(int timer_fd) {
    uint64_t expirations;
    while (read(timer_fd, &expirations, sizeof(expirations)) < 0 && errno == EINTR) {
    }

    uint64_t now = now_ms();
    dispatch_check_timeouts(now);

    // collect first, a tick may remove clients
    GList *vms = g_hash_table_get_values(vm_clients);
    for (GList *l = vms; l; l = l->next) {
        struct Client *vm = l->data;
        if (vm->type == CLIENT_QEMU) {
            monitor_tick_vm(vm, now);
        }
    }
    g_list_free(vms);
}

/*
 * subscriber and control clients
 */

// only root (or our own user, qmeventd itself runs as root) may control us
static bool require_root(struct Client *client, const char *what) {
    if (client->uid == 0 || client->uid == geteuid()) {
        return true;
    }
    fprintf(stderr, "pid%d: refusing '%s' from uid %d\n", client->pid, what, (int)client->uid);
    client->dead = true;
    return false;
}

static bool become_control(struct Client *client, ClientType type, const char *what) {
    if (!require_root(client, what)) {
        return false;
    }
    if (client->type != CLIENT_NONE && client->type != type) {
        fprintf(stderr, "pid%d: '%s' on a %d connection ignored\n", client->pid, what, client->type);
        return false;
    }
    client->state = STATE_IDLE;
    client->type = type;
    return true;
}

static void reply(struct Client *client, const char *error) {
    struct json_object *r = json_object_new_object();
    if (error) {
        json_object_object_add(r, "error", json_object_new_string(error));
    } else {
        json_object_object_add(r, "return", json_object_new_object());
    }
    queue_json(client, r);
    json_object_put(r);
}

static void handle_subscribe(struct Client *client) {
    if (!become_control(client, CLIENT_SUBSCRIBER, "subscribe")) {
        return;
    }
    if (!g_slist_find(subscribers, client)) {
        subscribers = g_slist_prepend(subscribers, client);
    }
    reply(client, NULL);
}

static const char *get_str(struct json_object *obj, const char *key) {
    struct json_object *v;
    if (!obj || !json_object_object_get_ex(obj, key, &v) || !json_object_is_type(v, json_type_string)) {
        return NULL;
    }
    return json_object_get_string(v);
}

// {"inject": {"vmid": "100", "event": "PRE_SNAPSHOT", "data": {...}}}
static void handle_inject(struct Client *client, struct json_object *req) {
    if (!become_control(client, CLIENT_CONTROL, "inject")) {
        return;
    }
    const char *vmid = get_str(req, "vmid");
    const char *event = get_str(req, "event");
    if (!vmid_valid(vmid)) {
        reply(client, "invalid vmid");
        return;
    }
    const struct event_info *info = lookup_event(event);
    if (!is_injectable(info)) {
        reply(client, "event not injectable");
        return;
    }
    struct json_object *data = NULL;
    json_object_object_get_ex(req, "data", &data);

    struct Client *vm = g_hash_table_lookup(vm_clients, vmid);
    if (vm && vm->type == CLIENT_QEMU) {
        mon_on_op_event(&vm->qemu.mon, now_ms(), info->name);
    } else {
        vm = NULL;
    }
    emit_event(vm, vmid, "api", info->name, data);
    reply(client, NULL);
}

// {"configure": {"vmid": "100", "dispatch": true, "heartbeat": {...}}}
static void handle_configure(struct Client *client, struct json_object *req) {
    if (!become_control(client, CLIENT_CONTROL, "configure")) {
        return;
    }
    const char *vmid = get_str(req, "vmid");
    struct Client *vm = vmid_valid(vmid) ? g_hash_table_lookup(vm_clients, vmid) : NULL;
    if (!vm || vm->type != CLIENT_QEMU) {
        reply(client, "VM not running");
        return;
    }

    struct json_object *hb_obj = NULL, *dispatch = NULL;
    struct MonHeartbeatConfig hb;
    json_object_object_get_ex(req, "heartbeat", &hb_obj);
    json_object_object_get_ex(req, "dispatch", &dispatch);
    mon_parse_heartbeat_config(hb_obj, &hb);
    mon_configure(&vm->qemu.mon, now_ms(), &hb, dispatch && json_object_get_boolean(dispatch));
    VERBOSE_PRINT("%s: configured (heartbeat: %d)\n", vmid, hb.enabled);
    reply(client, NULL);
}

// {"query": "status"} -> {"vms": {"100": {...}}}
static void handle_query(struct Client *client, struct json_object *req) {
    if (!become_control(client, CLIENT_CONTROL, "query")) {
        return;
    }
    if (!json_object_is_type(req, json_type_string) || strcmp(json_object_get_string(req), "status")) {
        reply(client, "unknown query");
        return;
    }

    struct json_object *vms = json_object_new_object();
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, vm_clients);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        struct Client *vm = value;
        if (vm->type != CLIENT_QEMU) {
            continue;
        }
        struct json_object *st = mon_state_json(&vm->qemu.mon);
        json_object_object_add(st, "pid", json_object_new_int(vm->pid));
        json_object_object_add(vms, vm->qemu.vmid, st);
    }
    struct json_object *r = json_object_new_object();
    json_object_object_add(r, "vms", vms);
    queue_json(client, r);
    json_object_put(r);
}

/*
 * VZDump specific client functions
 */

void handle_vzdump_handshake(struct Client *client, struct json_object *data) {
    client->state = STATE_IDLE;

    struct json_object *vmid_obj;
    json_bool has_vmid = data && json_object_object_get_ex(data, "vmid", &vmid_obj);

    if (!has_vmid) {
        VERBOSE_PRINT("pid%d: invalid vzdump handshake: no vmid\n", client->pid);
        return;
    }

    const char *vmid_str = json_object_get_string(vmid_obj);

    if (!vmid_str) {
        VERBOSE_PRINT("pid%d: invalid vzdump handshake: vmid is not a string\n", client->pid);
        return;
    }

    int res = snprintf(client->vzdump.vmid, sizeof(client->vzdump.vmid), "%s", vmid_str);
    if (res < 0 || res >= (int)sizeof(client->vzdump.vmid)) {
        VERBOSE_PRINT("pid%d: invalid vzdump handshake: vmid too long or invalid\n", client->pid);
        return;
    }

    struct Client *vmc = (struct Client *)g_hash_table_lookup(vm_clients, client->vzdump.vmid);
    if (vmc) {
        vmc->qemu.backup = true;

        // only mark as VZDUMP once we have set everything up, otherwise 'cleanup'
        // might try to access an invalid value
        client->type = CLIENT_VZDUMP;
        VERBOSE_PRINT("%s: vzdump backup started\n", client->vzdump.vmid);
    } else {
        VERBOSE_PRINT(
            "%s: vzdump requested backup start for unregistered VM\n", client->vzdump.vmid
        );
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
    client->ep_kind = EP_CLIENT;
    client->state = STATE_HANDSHAKE;
    client->type = CLIENT_NONE;
    client->fd = client_fd;
    client->pid = get_peer_from_fd(client_fd, &client->uid);
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

    if (client->qemu.probe) {
        struct Probe *probe = client->qemu.probe;
        log_neg(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, probe->fd, NULL), "epoll del probe");
        (void)close(probe->fd);
        free(probe);
        client->qemu.probe = NULL;
    }
    struct json_object *d = json_object_new_object();
    json_object_object_add(d, "graceful", json_object_new_boolean(graceful));
    json_object_object_add(d, "guest", json_object_new_boolean(guest));
    client->qemu.mon.run = RUN_STOPPING;
    report_suppressed(client);
    emit_event(client, client->qemu.vmid, "qmeventd", "EXITED", d);
    json_object_put(d);

    char vmid[sizeof(client->qemu.vmid)];
    strncpy(vmid, client->qemu.vmid, sizeof(vmid));
    g_hash_table_remove(vm_clients, &vmid); // frees key, ignore errors
    VERBOSE_PRINT("%s: executing cleanup (graceful: %d, guest: %d)\n", vmid, graceful, guest);

    int pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork failed: %s\n", strerror(errno));
        return;
    }
    if (pid == 0) {
        char *args[] = {
            (char *)qm_path, "cleanup", vmid, graceful ? "1" : "0", guest ? "1" : "0", NULL
        };

        execvp(qm_path, args);
        perror("execvp");
        _exit(1);
    }
}

void cleanup_client(struct Client *client) {
    log_neg(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client->fd, NULL), "epoll del");
    (void)close(client->fd);

    struct Client *vmc;
    switch (client->type) {
    case CLIENT_QEMU:
        cleanup_qemu_client(client);
        break;

    case CLIENT_VZDUMP:
        vmc = (struct Client *)g_hash_table_lookup(vm_clients, client->vzdump.vmid);
        if (vmc) {
            VERBOSE_PRINT("%s: backup ended\n", client->vzdump.vmid);
            vmc->qemu.backup = false;
            terminate_check(vmc);
        }
        break;

    case CLIENT_SUBSCRIBER:
        subscribers = g_slist_remove(subscribers, client);
        break;

    case CLIENT_CONTROL:
    case CLIENT_NONE:
        // do nothing, only close socket
        break;
    }

    if (client->out) {
        g_string_free(client->out, TRUE);
    }

    if (client->pidfd > 0) {
        (void)close(client->pidfd);
    }
    VERBOSE_PRINT("removing %s from forced cleanups\n", client->qemu.vmid);
    forced_cleanups = g_slist_remove(forced_cleanups, client);
    free(client);
}

void terminate_client(struct Client *client) {
    VERBOSE_PRINT("%s: terminating client (pid %d)\n", client->qemu.vmid, client->pid);

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
    VERBOSE_PRINT("%s: sending 'quit' via QMP\n", client->qemu.vmid);
    if (!must_write(client->fd, qmp_quit_command, sizeof(qmp_quit_command) - 1)) {
        VERBOSE_PRINT("%s: sending 'SIGTERM' to pid %d\n", client->qemu.vmid, client->pid);
        int err = kill(client->pid, SIGTERM);
        log_neg(err, "kill");
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
            log_neg((int)len, "read");
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
                    if (!handle_tagged_return(client, jobj, obj, false)) {
                        handle_qmp_return(client, obj, false);
                    }
                } else if (json_object_object_get_ex(jobj, "error", &obj)) {
                    if (!handle_tagged_return(client, jobj, obj, true)) {
                        handle_qmp_return(client, obj, true);
                    }
                } else if (json_object_object_get_ex(jobj, "vzdump", &obj)) {
                    handle_vzdump_handshake(client, obj);
                } else if (json_object_object_get_ex(jobj, "subscribe", &obj)) {
                    handle_subscribe(client);
                } else if (json_object_object_get_ex(jobj, "inject", &obj)) {
                    handle_inject(client, obj);
                } else if (json_object_object_get_ex(jobj, "configure", &obj)) {
                    handle_configure(client, obj);
                } else if (json_object_object_get_ex(jobj, "query", &obj)) {
                    handle_query(client, obj);
                } // else ignore message
            }
            break;
        case json_tokener_continue:
            if (client->buflen >= sizeof(client->buf)) {
                VERBOSE_PRINT("pid%d: msg too large, discarding buffer\n", client->pid);
                memset(client->buf, 0, sizeof(client->buf));
                client->buflen = 0;
            } // else we have enough space try again after next read
            break;
        default:
            VERBOSE_PRINT("pid%d: parse error: %d, discarding buffer\n", client->pid, jerr);
            memset(client->buf, 0, client->buflen);
            client->buflen = 0;
            break;
        }
        json_object_put(jobj);
        if (client->dead) {
            break;
        }
    }
    json_tokener_free(tok);

    if (client->dead) {
        cleanup_client(client);
    }
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
            fprintf(
                stderr, "SIGKILL cleanup of pid '%d' failed - %s\n", data->pid, strerror(errno)
            );
        }
    } else {
        fprintf(stderr, "cleanup failed, terminating pid '%d' with SIGKILL\n", data->pid);
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

int main(int argc, char *argv[]) {
    int opt;
    int daemonize = 1;
    char *socket_path = NULL;
    progname = argv[0];

    while ((opt = getopt(argc, argv, "hfvt:q:r:")) != -1) {
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
        case 'q':
            qm_path = optarg;
            break;
        case 'r':
            run_dir = optarg;
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
    signal(SIGPIPE, SIG_IGN);
    self_starttime = get_starttime(getpid());

    socket_path = argv[optind];

    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    bail_neg(sock, "socket");

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    unlink(socket_path);
    bail_neg(bind(sock, (struct sockaddr *)&addr, sizeof(addr)), "bind");

    struct epoll_event ev, events[1];
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    bail_neg(epoll_fd, "epoll_create1");

    ev.events = EPOLLIN;
    ev.data.ptr = &listen_tag;
    bail_neg(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev), "epoll_ctl");

    // drives the guest agent monitor
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    bail_neg(timer_fd, "timerfd_create");
    struct itimerspec tick = {.it_interval = {1, 0}, .it_value = {1, 0}};
    bail_neg(timerfd_settime(timer_fd, 0, &tick, NULL), "timerfd_settime");
    ev.events = EPOLLIN;
    ev.data.ptr = &timer_tag;
    bail_neg(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev), "epoll_ctl timer");

    bail_neg(listen(sock, 10), "listen");

    if (daemonize) {
        bail_neg(daemon(0, 1), "daemon");
    }

    qmeventd_log_init(STDOUT_FILENO);

    vm_clients = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
    dispatch_queues = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, dispatch_queue_free);

    int nevents;

    for (;;) {
        nevents = epoll_wait(epoll_fd, events, 1, needs_cleanup ? 10 * 1000 : -1);
        if (nevents < 0 && errno == EINTR) {
            continue;
        }
        bail_neg(nevents, "epoll_wait");

        for (int n = 0; n < nevents; n++) {
            EpollKind kind = *(EpollKind *)events[n].data.ptr;
            if (kind == EP_LISTEN) {
                int conn_sock = accept4(sock, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                log_neg(conn_sock, "accept");
                if (conn_sock > -1) {
                    add_new_client(conn_sock);
                }
            } else if (kind == EP_TIMER) {
                handle_timer(timer_fd);
            } else if (kind == EP_PROBE) {
                handle_probe((struct Probe *)events[n].data.ptr);
            } else if (kind == EP_DISPATCH) {
                handle_dispatch((struct DispatchQueue *)events[n].data.ptr);
            } else {
                struct Client *client = events[n].data.ptr;
                if ((events[n].events & EPOLLOUT) && !flush_output(client)) {
                    cleanup_client(client);
                    continue;
                }
                if (events[n].events & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
                    handle_client(client);
                }
            }
        }
        handle_forced_cleanup();
    }
}
