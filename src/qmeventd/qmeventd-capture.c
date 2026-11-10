// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    qmeventd -> private supervised capture-worker bridge.

    See qmeventd-capture.h for the contract. This file implements the trusted
    identity/generation registry, the bounded SOCK_SEQPACKET transport, the
    spawned/supervised worker and the validation of the worker's results.
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "qmeventd-capture.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif

#define QMEV_VMID_MAX 16
#define QMEV_STARTTIME_MAX 24

/* Worker -> parent accepted source/event vocabulary. Anything else is unsafe
 * and is rejected before it can reach the unified journal logger. */
static const char *const qmev_allowed_sources[] = {"qga", "capture"};
static const char *const qmev_allowed_events[] = {
    "HEARTBEAT_READY",  "HEARTBEAT_LOST",      "HEARTBEAT_RECOVERED", "SCREENSHOT_SAVED",
    "SCREENSHOT_FAILED", "SCREENSHOT_UNAVAILABLE", "SCREENSHOT_SKIPPED",
};

/* Lifecycle/panic/migration events forwarded to the worker. Forwarding is
 * independent of the journal logger and its rate limiting. */
static const char *const qmev_forwarded_events[] = {
    "SHUTDOWN",  "RESET",      "STOP",     "RESUME",    "SUSPEND",
    "SUSPEND_DISK", "WAKEUP",  "GUEST_PANICKED", "GUEST_CRASHLOADED",
    "MIGRATION", "MIGRATION_PASS",
};

struct qmev_vm_ident {
    char vmid[QMEV_VMID_MAX];
    pid_t pid;
    char starttime[QMEV_STARTTIME_MAX];
    uint64_t generation;
    bool backup;
};

struct qmev_packet {
    char *data;
    size_t len;
};

struct qmev_capture {
    struct qmev_capture_seams seams;

    int parent_fd; /* parent side of the private seqpacket pair, -1 if none */
    pid_t worker_pid;
    int worker_pidfd;

    uint64_t next_generation; /* parent-global, monotonic within daemon life */
    GHashTable *vms;          /* vmid -> struct qmev_vm_ident */

    struct qmev_packet queue[QMEV_CAPTURE_QUEUE_MAX];
    unsigned qhead;
    unsigned qcount;
    size_t qbytes;

    unsigned long long drop_since_summary;
    uint64_t next_drop_report_ms;

    bool want_worker; /* an observation was seen: a worker should be running */
    uint64_t backoff_ms;
    uint64_t next_retry_ms;
    bool spawn_fail_logged;
    bool lost_logged;
    uint64_t worker_start_ms;

    uint64_t worker_epoch; /* bumps on every successful spawn */
    int pidfd_ok;          /* 0 unknown, 1 supported, -1 cannot supervise (fail-closed) */

    /* daemon-owned private dups registered in the daemon's epoll set */
    int reg_fd;
    int reg_pidfd;
    int reg_src_fd; /* module fd reg_fd was dup'd from (change detection) */
    uint64_t reg_epoch;
    unsigned reg_events;

    /* resumable replay of known identities after a (re)start: a bounded queue
     * must never turn a burst of known VMs into a permanent miss. */
    char **replay_snapshot;
    size_t replay_count;
    size_t replay_cursor;
    /* a live observation could not be enqueued (queue full): resync the whole
     * set once the sink drains so it is never permanently blind */
    bool replay_dirty;

    struct qmev_capture_stats stats;
};

/* ------------------------------------------------------------------ */
/* default seams                                                      */
/* ------------------------------------------------------------------ */

static uint64_t default_now_ms(void *ud) {
    struct timespec ts;
    (void)ud;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static void default_log(
    void *ud,
    const char *vmid,
    pid_t qemu_pid,
    pid_t peer_pid,
    QLogLevel level,
    const char *source,
    const char *event,
    struct json_object *payload
) {
    (void)ud;
    qmeventd_log_event(vmid, qemu_pid, peer_pid, level, source, event, payload);
}

static int default_signal_worker(void *ud, int pidfd, pid_t pid, int sig) {
    (void)ud;
    (void)pid;
    if (pidfd >= 0) {
        return (int)syscall(__NR_pidfd_send_signal, pidfd, sig, NULL, 0);
    }
    errno = ENOTSUP;
    return -1;
}

static int default_open_pidfd(void *ud, pid_t pid) {
    (void)ud;
    return (int)syscall(__NR_pidfd_open, pid, 0);
}

static int default_pidfd_probe(void *ud) {
    (void)ud;
    /* capability probe: does the kernel support identity-stable process
     * handles at all? Uses our own pid, so it can never leak or signal
     * anything else. */
    return (int)syscall(__NR_pidfd_open, getpid(), 0);
}

/*
 * Production spawn. The child:
 *   1. arms PR_SET_PDEATHSIG so it can never outlive qmeventd,
 *   2. re-checks its parent to close the fork/PDEATHSIG race,
 *   3. dup2s the private endpoint onto stdin/stdout,
 *   4. closes every other inherited fd (no guest event socket may leak),
 *   5. execs only the fixed worker path (never an environment choice).
 */
static int default_spawn(void *ud, int *parent_fd_out, pid_t *pid_out) {
    int sv[2];
    pid_t parent;
    pid_t pid;
    (void)ud;

    if (qmev_make_worker_pair(sv) < 0) {
        return -1;
    }
    parent = getpid();
    pid = fork();
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        return -1;
    }
    if (pid == 0) {
        int wfd = sv[1];
        if (qmev_arm_child_lifetime(parent) != 0) {
            _exit(1); /* parent already gone, or prctl failed: do not orphan */
        }
        if (dup2(wfd, STDIN_FILENO) < 0 || dup2(wfd, STDOUT_FILENO) < 0) {
            _exit(1);
        }
        if (wfd > STDOUT_FILENO) {
            close(wfd);
        }
        qmev_close_fds_from(3);
        execl(QMEV_CAPTURE_WORKER_PATH, QMEV_CAPTURE_WORKER_PATH, (char *)NULL);
        _exit(127);
    }
    close(sv[1]);
    *parent_fd_out = sv[0];
    *pid_out = pid;
    return 0;
}

static void seams_fill_defaults(struct qmev_capture_seams *s) {
    if (!s->now_ms) {
        s->now_ms = default_now_ms;
    }
    if (!s->log) {
        s->log = default_log;
    }
    if (!s->signal_worker) {
        s->signal_worker = default_signal_worker;
    }
    if (!s->open_pidfd) {
        s->open_pidfd = default_open_pidfd;
    }
    if (!s->pidfd_probe) {
        s->pidfd_probe = default_pidfd_probe;
    }
    if (!s->spawn) {
        s->spawn = default_spawn;
    }
}

/* ------------------------------------------------------------------ */
/* small helpers                                                      */
/* ------------------------------------------------------------------ */

static uint64_t qmev_now(struct qmev_capture *c) { return c->seams.now_ms(c->seams.ud); }

static void emit_log(
    struct qmev_capture *c,
    const char *vmid,
    pid_t qemu_pid,
    QLogLevel level,
    const char *source,
    const char *event,
    struct json_object *payload
) {
    c->seams.log(c->seams.ud, vmid, qemu_pid, c->worker_pid, level, source, event, payload);
}

/* strict decimal token, capped length (no sign, no whitespace) */
static bool token_is_decimal(const char *s, size_t maxlen) {
    size_t n = 0;
    if (!s || !s[0]) {
        return false;
    }
    for (; *s; s++) {
        if (*s < '0' || *s > '9') {
            return false;
        }
        if (++n > maxlen) {
            return false;
        }
    }
    return true;
}

static bool worker_running(const struct qmev_capture *c) { return c->parent_fd >= 0; }

static void worker_lost(struct qmev_capture *c, const char *why);

static struct qmev_vm_ident *ident_lookup(struct qmev_capture *c, const char *vmid) {
    if (!vmid || !vmid[0]) {
        return NULL;
    }
    return (struct qmev_vm_ident *)g_hash_table_lookup(c->vms, vmid);
}

static struct qmev_vm_ident *ident_upsert(struct qmev_capture *c, const char *vmid) {
    struct qmev_vm_ident *id = ident_lookup(c, vmid);
    if (id) {
        return id;
    }
    id = g_malloc0(sizeof(*id));
    snprintf(id->vmid, sizeof(id->vmid), "%s", vmid);
    g_hash_table_insert(c->vms, g_strdup(vmid), id);
    return id;
}

/* ------------------------------------------------------------------ */
/* transport                                                          */
/* ------------------------------------------------------------------ */

static void account_ipc_drop(struct qmev_capture *c, unsigned long long n) {
    uint64_t now;
    c->stats.observations_dropped += n;
    c->drop_since_summary += n;
    now = qmev_now(c);
    if (c->drop_since_summary && now >= c->next_drop_report_ms) {
        struct json_object *p = json_object_new_object();
        json_object_object_add(
            p, "dropped", json_object_new_int64((int64_t)c->drop_since_summary)
        );
        json_object_object_add(p, "queued", json_object_new_int((int)c->qcount));
        emit_log(c, NULL, 0, QLOG_WARNING, "qmeventd", "CAPTURE_IPC_DROPPED", p);
        json_object_put(p);
        c->drop_since_summary = 0;
        c->next_drop_report_ms = now + 1000u;
    }
}

static void flush_queue(struct qmev_capture *c) {
    while (c->qcount > 0) {
        struct qmev_packet *p = &c->queue[c->qhead];
        ssize_t n = send(c->parent_fd, p->data, p->len, MSG_NOSIGNAL);
        if (n == (ssize_t)p->len) {
            c->qbytes -= p->len;
            free(p->data);
            p->data = NULL;
            p->len = 0;
            c->qhead = (c->qhead + 1u) % QMEV_CAPTURE_QUEUE_MAX;
            c->qcount--;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break; /* retried once the sink drains */
        }
        /* hard transport error: the worker endpoint is gone. worker_lost()
         * closes the endpoint, drops the queued observations (identities are
         * replayed on restart) and schedules a bounded retry. */
        worker_lost(c, "worker send failed");
        break;
    }
}

/* Enqueue result: 1 enqueued, 0 dropped for capacity (retryable), -1 too large
 * (permanent; never retried, so it must not trigger a resync). */
#define QMEV_ENQ_OK 1
#define QMEV_ENQ_FULL 0
#define QMEV_ENQ_TOOLARGE (-1)

static int enqueue_packet(struct qmev_capture *c, const char *buf, size_t len) {
    struct qmev_packet *p;

    if (len > QMEV_CAPTURE_PKT_MAX) {
        c->stats.packets_too_large++;
        account_ipc_drop(c, 1);
        return QMEV_ENQ_TOOLARGE;
    }
    if (c->qcount >= QMEV_CAPTURE_QUEUE_MAX || c->qbytes + len > QMEV_CAPTURE_QUEUE_BYTES_MAX) {
        /* A full queue must not become a deadlock: try to drain it before
         * declaring the observation lost. If the sink is still full the
         * observation is dropped (and reported) -- never buffered forever. */
        flush_queue(c);
    }
    if (c->qcount >= QMEV_CAPTURE_QUEUE_MAX || c->qbytes + len > QMEV_CAPTURE_QUEUE_BYTES_MAX) {
        account_ipc_drop(c, 1);
        return QMEV_ENQ_FULL;
    }
    p = &c->queue[(c->qhead + c->qcount) % QMEV_CAPTURE_QUEUE_MAX];
    p->data = malloc(len + 1);
    if (!p->data) {
        account_ipc_drop(c, 1);
        return QMEV_ENQ_FULL;
    }
    memcpy(p->data, buf, len);
    p->data[len] = '\0';
    p->len = len;
    c->qcount++;
    c->qbytes += len;
    c->stats.observations_sent++;
    flush_queue(c);
    return worker_running(c) ? QMEV_ENQ_OK : QMEV_ENQ_FULL;
}

static int build_and_enqueue(struct qmev_capture *c, struct json_object *obj) {
    const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
    int r = enqueue_packet(c, s ? s : "", s ? strlen(s) : 0);
    json_object_put(obj);
    return r;
}

static void add_identity_fields(struct json_object *obj, const struct qmev_vm_ident *id) {
    struct json_object *existing;
    json_object_object_add(obj, "vmid", json_object_new_int(atoi(id->vmid)));
    json_object_object_add(obj, "pid", json_object_new_int((int)id->pid));
    json_object_object_add(obj, "starttime", json_object_new_string(id->starttime));
    json_object_object_add(obj, "generation", json_object_new_int64((int64_t)id->generation));
    if (!json_object_object_get_ex(obj, "backup", &existing)) {
        json_object_object_add(obj, "backup", json_object_new_boolean(id->backup ? 1 : 0));
    }
}

static int enqueue_connected(struct qmev_capture *c, struct qmev_vm_ident *id) {
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "op", json_object_new_string("observe"));
    json_object_object_add(obj, "kind", json_object_new_string("connected"));
    add_identity_fields(obj, id);
    return build_and_enqueue(c, obj);
}

/* ------------------------------------------------------------------ */
/* worker supervision (lazy start)                                    */
/* ------------------------------------------------------------------ */

static void emit_worker_unavailable(struct qmev_capture *c, const char *reason) {
    struct json_object *p;
    if (c->spawn_fail_logged) {
        return;
    }
    p = json_object_new_object();
    json_object_object_add(p, "path", json_object_new_string(QMEV_CAPTURE_WORKER_PATH));
    json_object_object_add(p, "reason", json_object_new_string(reason ? reason : "unavailable"));
    json_object_object_add(p, "backoff_ms", json_object_new_int64((int64_t)c->backoff_ms));
    emit_log(c, NULL, 0, QLOG_WARNING, "qmeventd", "CAPTURE_WORKER_UNAVAILABLE", p);
    json_object_put(p);
    c->spawn_fail_logged = true;
}

static void replay_clear(struct qmev_capture *c) {
    size_t i;
    if (c->replay_snapshot) {
        for (i = 0; i < c->replay_count; i++) {
            g_free(c->replay_snapshot[i]);
        }
        g_free(c->replay_snapshot);
    }
    c->replay_snapshot = NULL;
    c->replay_count = 0;
    c->replay_cursor = 0;
}

/*
 * Snapshot the set of currently known identities to replay after a (re)start.
 * Only the vmid set is snapshotted; the identity itself (pid/starttime/
 * generation/backup) is re-read at send time, so a generation that advanced
 * during the replay is never sent stale.
 */
static void replay_start(struct qmev_capture *c) {
    GHashTableIter it;
    gpointer key;
    gpointer val;
    size_t i = 0;

    replay_clear(c);
    c->replay_count = g_hash_table_size(c->vms);
    if (c->replay_count == 0) {
        return;
    }
    c->replay_snapshot = g_new0(char *, c->replay_count);
    g_hash_table_iter_init(&it, c->vms);
    while (g_hash_table_iter_next(&it, &key, &val) && i < c->replay_count) {
        c->replay_snapshot[i++] = g_strdup((const char *)key);
    }
    c->replay_count = i;
    c->replay_cursor = 0;
}

/*
 * Advance the replay as far as the bounded outbound queue allows. When the
 * queue is full the cursor simply stops; the next tick resumes it. This is
 * what keeps a burst of known VMs (e.g. 2000 after a restart) from becoming a
 * permanent miss: nothing is discarded, it is only deferred.
 */
static void replay_pump(struct qmev_capture *c) {
    while (c->replay_snapshot && c->replay_cursor < c->replay_count) {
        struct qmev_vm_ident *id = ident_lookup(c, c->replay_snapshot[c->replay_cursor]);
        /* re-read the *current* identity; a vmid that disappeared meanwhile is
         * skipped, one whose generation advanced is sent with the new value */
        if (id && enqueue_connected(c, id) == QMEV_ENQ_FULL) {
            return; /* queue full: resume on the next tick (cursor preserved) */
        }
        c->replay_cursor++;
    }
    if (c->replay_snapshot) {
        replay_clear(c);
    }
}

/*
 * Attempt to make forward progress on the outbound path: drain what the sink
 * accepts, then resume a deferred replay (and re-snapshot once if a live
 * observation had to be deferred). Safe to call from any observation entry
 * point and from the supervision tick; never blocks and is bounded by the
 * queue.
 */
static void drive_replay(struct qmev_capture *c) {
    if (c->parent_fd < 0) {
        return;
    }
    flush_queue(c);
    if (!c->replay_snapshot && c->replay_dirty) {
        c->replay_dirty = false;
        replay_start(c);
    }
    replay_pump(c);
}

/*
 * Ensure a worker is running. Returns true when it was just started (so the
 * caller must not also emit an observation for the identity that triggered
 * the start: replay_start() already covered it).
 */
static bool ensure_worker(struct qmev_capture *c) {
    uint64_t now;
    int fd = -1;
    pid_t pid = -1;

    if (worker_running(c)) {
        return false;
    }
    if (c->pidfd_ok < 0) {
        return false; /* fail-closed: no identity-proven way to supervise */
    }
    now = qmev_now(c);
    if (c->next_retry_ms && now < c->next_retry_ms) {
        return false; /* inside the bounded backoff window */
    }
    if (c->pidfd_ok == 0) {
        int probe = c->seams.pidfd_probe(c->seams.ud);
        if (probe < 0) {
            /* no pidfd => a worker could never be signalled by identity, and a
             * raw (reusable) PID must never be killed, so the worker stays
             * disabled rather than risk signalling the wrong process. */
            c->pidfd_ok = -1;
            emit_worker_unavailable(c, "pidfd unsupported: worker disabled");
            return false;
        }
        close(probe);
        c->pidfd_ok = 1;
    }
    if (c->seams.spawn(c->seams.ud, &fd, &pid) != 0 || fd < 0) {
        c->stats.worker_failures++;
        if (c->backoff_ms < QMEV_CAPTURE_BACKOFF_MIN_MS) {
            c->backoff_ms = QMEV_CAPTURE_BACKOFF_MIN_MS;
        } else if (c->backoff_ms < QMEV_CAPTURE_BACKOFF_MAX_MS) {
            c->backoff_ms *= 2u;
            if (c->backoff_ms > QMEV_CAPTURE_BACKOFF_MAX_MS) {
                c->backoff_ms = QMEV_CAPTURE_BACKOFF_MAX_MS;
            }
        }
        c->next_retry_ms = now + c->backoff_ms;
        emit_worker_unavailable(c, "spawn failed");
        return false;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        close(fd);
        return false;
    }
    c->parent_fd = fd;
    c->worker_pid = pid;
    c->worker_pidfd = c->seams.open_pidfd(c->seams.ud, pid); /* may fail */
    /* If no identity-stable handle could be opened the worker may still run,
     * but it must never be raw-PID-killed and must never be duplicated. */
    c->worker_epoch++;
    c->worker_start_ms = now;
    c->stats.worker_spawns++;
    /* A successful fork does not prove a healthy worker. Reset the backoff
     * only after a long-lived worker exits, not on every crash-loop spawn. */
    c->next_retry_ms = 0;
    c->spawn_fail_logged = false;
    c->lost_logged = false;
    c->replay_dirty = false;
    replay_start(c);
    replay_pump(c);
    return true;
}

/*
 * The worker endpoint is gone (EOF, hard send/recv error, or a readable
 * pidfd). Release the fds, drop the pending observations (identities are
 * replayed on restart; events are forensic-only), and schedule a bounded
 * retry. Only a whole process is ever signalled, and only through its own
 * pidfd (see qmev_capture_free/qmev_capture_tick), never a bare reused PID.
 */
static void drop_queue(struct qmev_capture *c) {
    while (c->qcount > 0) {
        struct qmev_packet *p = &c->queue[c->qhead];
        free(p->data);
        p->data = NULL;
        p->len = 0;
        c->qhead = (c->qhead + 1u) % QMEV_CAPTURE_QUEUE_MAX;
        c->qcount--;
    }
    c->qbytes = 0;
}

static void worker_lost(struct qmev_capture *c, const char *why) {
    uint64_t now;
    bool had_pidfd = c->worker_pidfd >= 0;
    if (c->parent_fd < 0 && c->worker_pidfd < 0) {
        return;
    }
    if (c->parent_fd >= 0) {
        close(c->parent_fd);
    }
    c->parent_fd = -1;
    if (c->worker_pidfd >= 0) {
        /* The pidfd names exactly this process, so a reused PID can never be
         * signalled by mistake. A worker whose IPC endpoint died but which is
         * still lingering is terminated here; an already-exited one is a
         * harmless ESRCH. */
        c->seams.signal_worker(c->seams.ud, c->worker_pidfd, c->worker_pid, SIGTERM);
        close(c->worker_pidfd);
    }
    c->worker_pidfd = -1;
    c->worker_pid = 0;
    replay_clear(c);
    c->replay_dirty = false;
    if (c->qcount) {
        account_ipc_drop(c, c->qcount);
    }
    drop_queue(c);

    now = qmev_now(c);
    if (!had_pidfd) {
        /* No identity-stable handle for the worker that just went away: there
         * is no way to prove a later spawn is a *different* process, and the
         * old worker must never be raw-PID-killed. Fail closed and stop
         * spawning so a duplicate worker can never be created. */
        c->pidfd_ok = -1;
        c->next_retry_ms = 0;
        c->want_worker = true;
        emit_worker_unavailable(c, "unsupervised worker lost: capture disabled");
        return;
    }

    /* a worker that ran for a long time is not crash-looping: do not punish it
     * with a grown backoff */
    if (c->worker_start_ms && now - c->worker_start_ms < QMEV_CAPTURE_BACKOFF_MAX_MS) {
        if (c->backoff_ms < QMEV_CAPTURE_BACKOFF_MAX_MS) {
            c->backoff_ms *= 2u;
            if (c->backoff_ms > QMEV_CAPTURE_BACKOFF_MAX_MS) {
                c->backoff_ms = QMEV_CAPTURE_BACKOFF_MAX_MS;
            }
        }
    } else {
        c->backoff_ms = QMEV_CAPTURE_BACKOFF_MIN_MS;
    }
    c->next_retry_ms = now + c->backoff_ms;
    c->want_worker = true;

    if (!c->lost_logged) {
        struct json_object *p = json_object_new_object();
        json_object_object_add(
            p, "reason", json_object_new_string(why ? why : "worker endpoint closed")
        );
        json_object_object_add(p, "retry_ms", json_object_new_int64((int64_t)c->backoff_ms));
        emit_log(c, NULL, 0, QLOG_WARNING, "qmeventd", "CAPTURE_WORKER_LOST", p);
        json_object_put(p);
        c->lost_logged = true;
    }
}

/* ------------------------------------------------------------------ */
/* public: lifecycle                                                  */
/* ------------------------------------------------------------------ */

struct qmev_capture *qmev_capture_new(const struct qmev_capture_seams *seams) {
    struct qmev_capture *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    if (seams) {
        c->seams = *seams;
    }
    seams_fill_defaults(&c->seams);
    c->parent_fd = -1;
    c->worker_pidfd = -1;
    c->reg_fd = -1;
    c->reg_pidfd = -1;
    c->backoff_ms = QMEV_CAPTURE_BACKOFF_MIN_MS;
    c->vms = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    return c;
}

void qmev_capture_free(struct qmev_capture *c) {
    unsigned i;
    if (!c) {
        return;
    }
    if (c->parent_fd >= 0) {
        close(c->parent_fd);
    }
    if (c->worker_pidfd >= 0) {
        close(c->worker_pidfd);
    }
    if (c->reg_fd >= 0) {
        close(c->reg_fd); /* closing also removes it from any epoll set */
    }
    if (c->reg_pidfd >= 0) {
        close(c->reg_pidfd);
    }
    replay_clear(c);
    for (i = 0; i < c->qcount; i++) {
        free(c->queue[(c->qhead + i) % QMEV_CAPTURE_QUEUE_MAX].data);
    }
    g_hash_table_destroy(c->vms);
    free(c);
}

bool qmev_capture_observe_connected(
    struct qmev_capture *c, const char *vmid, pid_t pid, const char *starttime
) {
    struct qmev_vm_ident *id;
    bool started;
    int enq;

    if (!c || !token_is_decimal(vmid, QMEV_VMID_MAX - 1)) {
        return false;
    }
    if (pid <= 0) {
        return false;
    }
    if (!token_is_decimal(starttime, QMEV_STARTTIME_MAX - 1)) {
        return false;
    }

    id = ident_upsert(c, vmid);
    id->pid = pid;
    snprintf(id->starttime, sizeof(id->starttime), "%s", starttime);
    id->generation = ++c->next_generation; /* new connection: new generation */
    id->backup = false;

    c->want_worker = true;
    started = ensure_worker(c);
    if (started) {
        return true; /* replay_start() already forwarded this identity */
    }
    if (!worker_running(c)) {
        return false; /* will be replayed once the worker comes up */
    }
    enq = enqueue_connected(c, id);
    if (enq == QMEV_ENQ_FULL) {
        c->replay_dirty = true; /* re-synced once the sink drains */
    }
    drive_replay(c);
    return enq == QMEV_ENQ_OK;
}

uint64_t qmev_capture_generation(const struct qmev_capture *c, const char *vmid) {
    struct qmev_vm_ident *id = ident_lookup((struct qmev_capture *)c, vmid);
    return id ? id->generation : 0;
}

int qmev_capture_worker_fd(const struct qmev_capture *c) { return c ? c->parent_fd : -1; }

int qmev_capture_worker_pidfd(const struct qmev_capture *c) { return c ? c->worker_pidfd : -1; }

/* ------------------------------------------------------------------ */
/* epoll registration (owned by the module, keyed by lifetime)        */
/* ------------------------------------------------------------------ */

static int cap_io_token;
static int cap_pidfd_token;

void *qmev_capture_io_token(void) { return &cap_io_token; }
void *qmev_capture_pidfd_token(void) { return &cap_pidfd_token; }

static int dup_cloexec(int fd) { return fcntl(fd, F_DUPFD_CLOEXEC, 3); }

/*
 * Keep the daemon's epoll set in sync with the worker's fds. The module never
 * registers its own volatile endpoint fd; it registers a private dup() it owns
 * and only ever EPOLL_CTL_DELs+close()s that dup. Because the dup stays open
 * (its number cannot be handed to a new client) and is DELeted before it is
 * closed, a number reused by an unrelated client can never be mis-DELeted, and
 * a respawned worker that lands on a previously-used number is still detected
 * through the spawn epoch and re-ADDed.
 */
void qmev_capture_epoll_sync(struct qmev_capture *c, int epoll_fd) {
    uint64_t want_epoch;

    if (!c || epoll_fd < 0) {
        return;
    }
    want_epoch = c->worker_epoch;

    /* --- worker IO endpoint --- */
    {
        int cur = c->parent_fd;
        if (c->reg_fd >= 0 &&
            (cur < 0 || c->reg_src_fd != cur || c->reg_epoch != want_epoch)) {
            (void)epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->reg_fd, NULL);
            close(c->reg_fd);
            c->reg_fd = -1;
        }
        if (c->reg_fd < 0 && cur >= 0) {
            int nfd = dup_cloexec(cur);
            if (nfd >= 0) {
                struct epoll_event e;
                e.events = EPOLLIN;
                e.data.ptr = &cap_io_token;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, nfd, &e) == 0) {
                    c->reg_fd = nfd;
                    c->reg_src_fd = cur;
                    c->reg_events = EPOLLIN;
                } else {
                    close(nfd);
                }
            }
        } else if (c->reg_fd >= 0) {
            /* add EPOLLOUT while a backlog exists so the daemon is woken to
             * drain it even with no new observations read */
            unsigned want = EPOLLIN | (c->qcount > 0 ? EPOLLOUT : 0);
            if (want != c->reg_events) {
                struct epoll_event e;
                e.events = want;
                e.data.ptr = &cap_io_token;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, c->reg_fd, &e) == 0) {
                    c->reg_events = want;
                }
            }
        }
    }

    /* --- worker pidfd --- */
    {
        int cur = c->worker_pidfd;
        if (c->reg_pidfd >= 0 && (cur < 0 || c->reg_epoch != want_epoch)) {
            (void)epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->reg_pidfd, NULL);
            close(c->reg_pidfd);
            c->reg_pidfd = -1;
        }
        if (c->reg_pidfd < 0 && cur >= 0) {
            int nfd = dup_cloexec(cur);
            if (nfd >= 0) {
                struct epoll_event e;
                e.events = EPOLLIN;
                e.data.ptr = &cap_pidfd_token;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, nfd, &e) == 0) {
                    c->reg_pidfd = nfd;
                } else {
                    close(nfd);
                }
            }
        }
    }

    c->reg_epoch = want_epoch;
}

/* ------------------------------------------------------------------ */
/* observation forwarding                                             */
/* ------------------------------------------------------------------ */

static bool event_forwarded(const char *s) {
    size_t i;
    if (!s) {
        return false;
    }
    for (i = 0; i < sizeof(qmev_forwarded_events) / sizeof(qmev_forwarded_events[0]); i++) {
        if (!strcmp(s, qmev_forwarded_events[i])) {
            return true;
        }
    }
    return false;
}

bool qmev_capture_observe_event(
    struct qmev_capture *c, const char *vmid, const char *event, struct json_object *full_event
) {
    struct qmev_vm_ident *id;
    struct json_object *obj;
    int enq;

    if (!c || !vmid || !event) {
        return false;
    }
    id = ident_lookup(c, vmid);
    if (!id) {
        return false; /* unauthenticated / unassociated client: never forward */
    }
    if (!strcmp(event, "RESET")) {
        /* a guest reboot advances the generation even when the PID is unchanged */
        id->generation = ++c->next_generation;
    }
    if (!event_forwarded(event)) {
        return false;
    }
    c->want_worker = true;
    ensure_worker(c);
    if (!worker_running(c)) {
        return false;
    }
    obj = json_object_new_object();
    json_object_object_add(obj, "op", json_object_new_string("observe"));
    json_object_object_add(obj, "kind", json_object_new_string("event"));
    add_identity_fields(obj, id);
    json_object_object_add(
        obj, "event", full_event ? json_object_get(full_event) : json_object_new_object()
    );
    enq = build_and_enqueue(c, obj);
    if (enq == QMEV_ENQ_FULL) {
        c->replay_dirty = true; /* re-sync the identity set after congestion */
    }
    drive_replay(c);
    return enq == QMEV_ENQ_OK;
}

bool qmev_capture_observe_disconnected(struct qmev_capture *c, const char *vmid) {
    struct qmev_vm_ident *id;
    struct json_object *obj;
    int enq = QMEV_ENQ_FULL;

    if (!c || !vmid) {
        return false;
    }
    id = ident_lookup(c, vmid);
    if (!id) {
        return false;
    }
    c->want_worker = true;
    ensure_worker(c);
    if (worker_running(c)) {
        obj = json_object_new_object();
        json_object_object_add(obj, "op", json_object_new_string("observe"));
        json_object_object_add(obj, "kind", json_object_new_string("disconnected"));
        add_identity_fields(obj, id);
        enq = build_and_enqueue(c, obj);
        if (enq == QMEV_ENQ_FULL) {
            c->replay_dirty = true;
        }
    }
    /* forget the identity: a late result for it must not attach to the next
     * VM incarnation that reuses this vmid */
    g_hash_table_remove(c->vms, vmid);
    if (enq == QMEV_ENQ_FULL && worker_running(c)) {
        /* A replay of only live identities cannot remove a ghost VM whose
         * disconnect was dropped. Recreate the worker from the live set. */
        worker_lost(c, "disconnect queue overflow; resynchronising worker");
    }
    drive_replay(c);
    return enq == QMEV_ENQ_OK;
}

bool qmev_capture_observe_backup(struct qmev_capture *c, const char *vmid, bool active) {
    struct qmev_vm_ident *id;
    struct json_object *obj;
    int enq;

    if (!c || !vmid) {
        return false;
    }
    id = ident_lookup(c, vmid);
    if (!id) {
        return false; /* only a registered QEMU identity can back up */
    }
    id->backup = active;
    c->want_worker = true;
    ensure_worker(c);
    if (!worker_running(c)) {
        return false;
    }
    obj = json_object_new_object();
    json_object_object_add(obj, "op", json_object_new_string("observe"));
    json_object_object_add(obj, "kind", json_object_new_string("backup"));
    add_identity_fields(obj, id); /* maps to the QEMU pid/starttime/generation */
    enq = build_and_enqueue(c, obj);
    if (enq == QMEV_ENQ_FULL) {
        c->replay_dirty = true; /* re-sync the identity set after congestion */
    }
    drive_replay(c);
    return enq == QMEV_ENQ_OK;
}

/*
 * Worker -> parent result validation. A packet is only logged when it names
 * the *current* trusted identity (vmid + pid + starttime + generation) and
 * uses the safe vocabulary. Stale results never attach to a new VM
 * incarnation; unsafe source/event/level (or any non-"log" op) is rejected.
 */
static bool source_allowed(const char *s) {
    size_t i;
    if (!s) {
        return false;
    }
    for (i = 0; i < sizeof(qmev_allowed_sources) / sizeof(qmev_allowed_sources[0]); i++) {
        if (!strcmp(s, qmev_allowed_sources[i])) {
            return true;
        }
    }
    return false;
}

static bool event_allowed(const char *s) {
    size_t i;
    if (!s) {
        return false;
    }
    for (i = 0; i < sizeof(qmev_allowed_events) / sizeof(qmev_allowed_events[0]); i++) {
        if (!strcmp(s, qmev_allowed_events[i])) {
            return true;
        }
    }
    return false;
}

/*
 * The allowed vocabulary is only meaningful in pairs: heartbeat results come
 * from the QGA source, screenshots from the capture source. A worker that
 * claims a screenshot came from a guest agent (or vice versa) is inconsistent
 * and rejected, so a compromised worker cannot mislabel its provenance.
 */
static bool source_event_paired(const char *source, const char *event) {
    if (!source || !event) {
        return false;
    }
    if (!strcmp(source, "qga")) {
        return strncmp(event, "HEARTBEAT_", 10) == 0;
    }
    if (!strcmp(source, "capture")) {
        return strncmp(event, "SCREENSHOT_", 11) == 0;
    }
    return false;
}

static bool parse_level(const char *s, QLogLevel *out) {
    if (!s) {
        return false;
    }
    if (!strcmp(s, "info")) {
        *out = QLOG_INFO;
        return true;
    }
    if (!strcmp(s, "warning")) {
        *out = QLOG_WARNING;
        return true;
    }
    if (!strcmp(s, "error")) {
        *out = QLOG_ERROR;
        return true;
    }
    return false;
}

static void handle_result_packet(struct qmev_capture *c, const char *buf, size_t len) {
    struct json_tokener *tok = json_tokener_new();
    struct json_object *obj;
    struct json_object *v;
    char vmidstr[QMEV_VMID_MAX];
    struct qmev_vm_ident *id;
    QLogLevel level;
    const char *source;
    const char *event;
    struct json_object *payload = NULL;
    obj = tok ? json_tokener_parse_ex(tok, buf, (int)len) : NULL;
    if (!tok || json_tokener_get_error(tok) != json_tokener_success || !obj ||
        !json_object_is_type(obj, json_type_object)) {
        c->stats.results_invalid++;
        json_object_put(obj);
        json_tokener_free(tok);
        return;
    }
    json_tokener_free(tok);

    /* the only op a worker may use is "log"; never quit/reset/kill a VM */
    if (!json_object_object_get_ex(obj, "op", &v) ||
        json_object_get_type(v) != json_type_string || strcmp(json_object_get_string(v), "log")) {
        c->stats.results_invalid++;
        json_object_put(obj);
        return;
    }

    /* trusted identity: vmid + pid + starttime + generation must all match */
    if (!json_object_object_get_ex(obj, "vmid", &v) ||
        json_object_get_type(v) != json_type_int) {
        c->stats.results_invalid++;
        json_object_put(obj);
        return;
    }
    snprintf(vmidstr, sizeof(vmidstr), "%lld", (long long)json_object_get_int64(v));
    id = ident_lookup(c, vmidstr);
    if (!id) {
        c->stats.results_stale++;
        json_object_put(obj);
        return;
    }
    if (!json_object_object_get_ex(obj, "pid", &v) || json_object_get_type(v) != json_type_int ||
        (pid_t)json_object_get_int64(v) != id->pid ||
        !json_object_object_get_ex(obj, "starttime", &v) ||
        json_object_get_type(v) != json_type_string ||
        strcmp(json_object_get_string(v), id->starttime) ||
        !json_object_object_get_ex(obj, "generation", &v) ||
        json_object_get_type(v) != json_type_int ||
        (uint64_t)json_object_get_int64(v) != id->generation) {
        c->stats.results_stale++;
        json_object_put(obj);
        return;
    }

    /* safe vocabulary only */
    source = json_object_object_get_ex(obj, "source", &v) ? json_object_get_string(v) : NULL;
    event = json_object_object_get_ex(obj, "event", &v) ? json_object_get_string(v) : NULL;
    if (!parse_level(
            json_object_object_get_ex(obj, "level", &v) ? json_object_get_string(v) : NULL, &level
        ) ||
        !source_allowed(source) || !event_allowed(event) || !source_event_paired(source, event)) {
        c->stats.results_invalid++;
        json_object_put(obj);
        return;
    }

    (void)json_object_object_get_ex(obj, "payload", &payload);
    emit_log(c, id->vmid, id->pid, level, source, event, payload);
    c->stats.results_accepted++;
    json_object_put(obj);

}

void qmev_capture_handle_readable(struct qmev_capture *c) {
    int budget = QMEV_CAPTURE_READ_BUDGET;
    if (!c || c->parent_fd < 0) {
        return;
    }
    for (;;) {
        char buf[QMEV_CAPTURE_PKT_MAX + 1];
        ssize_t n;
        if (budget <= 0) {
            /* A worker that streams messages must never be able to monopolise
             * the daemon loop: stop here and let the next EPOLLIN pick up the
             * remainder (the socket keeps the rest queued). */
            break;
        }
        n = recv(c->parent_fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break; /* nothing more to read */
            }
            /* any other error: the endpoint is gone */
            worker_lost(c, "worker link error");
            break;
        }
        if (n == 0) {
            worker_lost(c, "worker closed the link");
            break;
        }
        budget--;
        if ((size_t)n > QMEV_CAPTURE_PKT_MAX) {
            c->stats.results_invalid++;
            continue;
        }
        handle_result_packet(c, buf, (size_t)n);
    }
}

/*
 * Bounded supervision step, called from the daemon's main loop (and on a
 * bounded epoll timeout). It detects a dead endpoint/process non-blockingly,
 * flushes the bounded queue, and retries the spawn inside the backoff window.
 * It never blocks and never touches the QMP control state machine.
 */
void qmev_capture_tick(struct qmev_capture *c) {
    if (!c || !c->want_worker) {
        return;
    }
    if (c->drop_since_summary) {
        account_ipc_drop(c, 0);
    }
    if (c->parent_fd >= 0) {
        if (c->worker_pidfd >= 0) {
            struct pollfd p;
            p.fd = c->worker_pidfd;
            p.events = POLLIN;
            p.revents = 0;
            if (poll(&p, 1, 0) > 0 && (p.revents & (POLLIN | POLLHUP | POLLERR))) {
                /* the pidfd belongs to exactly this process: no reused PID can
                 * be mistaken for our worker */
                worker_lost(c, "worker process exited");
            }
        }
        if (c->parent_fd >= 0) {
            struct pollfd q;
            q.fd = c->parent_fd;
            q.events = POLLIN;
            q.revents = 0;
            if (poll(&q, 1, 0) > 0 && (q.revents & (POLLIN | POLLHUP | POLLERR))) {
                qmev_capture_handle_readable(c); /* EOF/error closes the worker */
            }
        }
        if (c->parent_fd >= 0) {
            /* Drain the bounded outbound queue and resume a deferred replay.
             * This must not depend on a new observation arriving or on
             * EPOLLOUT: a full queue would otherwise never be flushed (the
             * deadlock the raw enqueue-only flush path caused), and a burst of
             * known VMs would be lost permanently. */
            drive_replay(c);
        }
    }
    if (c->parent_fd < 0) {
        ensure_worker(c); /* no-op inside the backoff window */
    }
}

int qmev_capture_wait_timeout_ms(const struct qmev_capture *c) {
    uint64_t now;
    if (!c || !c->want_worker || c->pidfd_ok < 0) {
        return -1; /* no worker (or none possible): no timing opinion */
    }
    if (c->parent_fd < 0) {
        now = c->seams.now_ms(c->seams.ud);
        if (c->next_retry_ms > now) {
            uint64_t d = c->next_retry_ms - now;
            return d > 1000u ? 1000 : (int)d;
        }
        return 0;
    }
    if (c->qcount > 0 || c->drop_since_summary > 0) {
        return 100; /* drain a backlog promptly */
    }
    return 1000; /* periodic supervision */
}

void qmev_capture_get_stats(const struct qmev_capture *c, struct qmev_capture_stats *out) {
    if (out && c) {
        *out = c->stats;
    }
}

/*
 * Create the private worker socketpair. Both ends are CLOEXEC so that no
 * unrelated fork+exec in the daemon (notably the `qm cleanup` helper) can
 * inherit the worker's IPC endpoint and keep it alive past the worker's death.
 */
int qmev_make_worker_pair(int sv[2]) {
    if (sv == NULL) {
        return -1;
    }
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) == 0) {
        return 0;
    }
    /* ancient kernels without SOCK_CLOEXEC: fall back to an explicit flag */
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0) {
        return -1;
    }
    (void)fcntl(sv[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(sv[1], F_SETFD, FD_CLOEXEC);
    return 0;
}

/*
 * Close every fd >= first_fd, except the /proc/self/fd directory fd itself.
 * This is what keeps a spawned worker from inheriting any guest event socket.
 */
void qmev_close_fds_from(int first_fd) {
    DIR *d = opendir("/proc/self/fd");
    if (d) {
        int keep = dirfd(d);
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            long fd;
            if (ent->d_name[0] < '0' || ent->d_name[0] > '9') {
                continue;
            }
            fd = strtol(ent->d_name, NULL, 10);
            if (fd >= first_fd && (int)fd != keep) {
                close((int)fd);
            }
        }
        closedir(d);
    } else {
        int fd;
        for (fd = first_fd; fd < 1024; fd++) {
            close(fd);
        }
    }
}

int qmev_arm_child_lifetime(pid_t parent_pid) {
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) {
        return -1;
    }
    /* the parent could have died between fork() and prctl(): if so, PDEATHSIG
     * will never fire, so the child must exit by itself */
    if (getppid() != parent_pid) {
        return 1;
    }
    return 0;
}

int qmev_read_starttime(pid_t pid, char *out, size_t outlen) {
    char path[64];
    char buf[4096];
    char *p;
    char *rp;
    size_t n;
    FILE *f;
    int field;

    if (!out || outlen == 0) {
        return -1;
    }
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    f = fopen(path, "r");
    if (!f) {
        return -1;
    }
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    /* comm may contain spaces/parens: everything after the LAST ')' is the
     * fixed field list; starttime is field 22, i.e. the 20th token after ')'. */
    rp = strrchr(buf, ')');
    if (!rp) {
        return -1;
    }
    p = rp + 1;
    for (field = 1; field <= 20; field++) {
        char *start;
        size_t len;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (!*p || *p == '\n') {
            return -1;
        }
        start = p;
        while (*p && *p != ' ' && *p != '\n' && *p != '\t') {
            p++;
        }
        len = (size_t)(p - start);
        if (field == 20) {
            if (len == 0 || len >= outlen) {
                return -1;
            }
            memcpy(out, start, len);
            out[len] = '\0';
            return 0;
        }
    }
    return -1;
}
