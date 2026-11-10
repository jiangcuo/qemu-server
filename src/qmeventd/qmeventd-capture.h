// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    qmeventd -> private supervised capture-worker bridge.

    qmeventd owns the trusted VM identity (vmid + QEMU pid + /proc starttime)
    and a parent-global *generation* counter. It forwards lifecycle, panic and
    backup *observations* to a fixed, supervised worker over a private
    AF_UNIX SOCK_SEQPACKET socketpair, and validates the worker's log results
    against the current identity/generation before handing them to the unified
    journal logger. The worker can never ask qmeventd to quit/reset/kill a VM:
    the only accepted op is "log".

    Design rules (see plans/qmeventd-heartbeat-panic-capture-plan.md and the
    parent-owned contract):

      * The worker executable is fixed (/usr/libexec/qemu-server/qmeventd-worker
        by default); it is never selected from the environment.
      * Sending is non-blocking with MSG_NOSIGNAL; the outbound queue, the
        packet size and the replay of known VMs are all bounded.
      * All unrelated fds are closed in the child before exec, so no guest
        event socket is leaked into the worker.
      * A worker is only ever signalled through its own pidfd/identity, never a
        bare reused PID. It is supervised with bounded exponential backoff so a
        missing/broken worker can never spin the daemon.

    The module is independently testable: process side effects (spawn, signal,
    clock, journal) are injected through `struct qmev_capture_seams`.
*/

#ifndef QMEVENTD_CAPTURE_H
#define QMEVENTD_CAPTURE_H

#include <json.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "qmeventd-log.h"

/* Fixed production worker; never chosen from the environment. */
#define QMEV_CAPTURE_WORKER_PATH "/usr/libexec/qemu-server/qmeventd-worker"

/* One compact JSON object per SOCK_SEQPACKET packet. */
#define QMEV_CAPTURE_PKT_MAX 65536

/* Bounded outbound queue. */
#define QMEV_CAPTURE_QUEUE_MAX 1024
#define QMEV_CAPTURE_QUEUE_BYTES_MAX (4u * 1024u * 1024u)

/* One readable callback processes at most this many worker packets, so a
 * worker (or a compromised worker) that streams messages can never starve the
 * daemon's QMP control loop. The remainder stays queued in the socket and is
 * picked up by the next EPOLLIN. */
#define QMEV_CAPTURE_READ_BUDGET 200

/* Bounded, restart-safe supervision backoff (milliseconds). */
#define QMEV_CAPTURE_BACKOFF_MIN_MS 1000u
#define QMEV_CAPTURE_BACKOFF_MAX_MS 60000u

struct qmev_capture;

/*
 * Injected side effects. Every member may be NULL, in which case the
 * production implementation is used. `ud` is passed back verbatim.
 */
struct qmev_capture_seams {
    /*
     * Spawn the supervised worker. On success return 0, set *parent_fd_out to
     * the parent side of the private SOCK_SEQPACKET socketpair and *pid_out to
     * the child pid. The child must arm PR_SET_PDEATHSIG, re-verify its
     * parent, close every unrelated fd and exec only the fixed worker path.
     */
    int (*spawn)(void *ud, int *parent_fd_out, pid_t *pid_out);
    /* Journal sink; NULL selects qmeventd_log_event(). */
    void (*log)(void *ud, const char *vmid, pid_t qemu_pid, pid_t peer_pid, QLogLevel level,
                const char *source, const char *event, struct json_object *payload);
    /* Monotonic milliseconds; NULL selects clock_gettime(CLOCK_MONOTONIC). */
    uint64_t (*now_ms)(void *ud);
    /* Open an identity-stable handle for a spawned worker; NULL selects the
     * pidfd_open() syscall. A pidfd refers to exactly one process, so it can
     * never be confused with a later reused PID. */
    int (*open_pidfd)(void *ud, pid_t pid);
    /* Probe pidfd availability for supervision. >=0 means supported (the
     * caller closes the returned fd); <0 means unsupported. NULL selects the
     * real pidfd_open() syscall. Without pidfd support there is no
     * identity-proven way to signal a worker, so the worker is disabled
     * (fail-closed) instead of ever being killed through a reused raw PID. */
    int (*pidfd_probe)(void *ud);
    /* Deliver a signal to the supervised worker; NULL selects the pidfd path. */
    int (*signal_worker)(void *ud, int pidfd, pid_t pid, int sig);
    void *ud;
};

struct qmev_capture_stats {
    unsigned long long observations_sent;
    unsigned long long observations_dropped; /* queue/packet boundary losses */
    unsigned long long packets_too_large;
    unsigned long long results_accepted;
    unsigned long long results_stale;
    unsigned long long results_invalid;
    unsigned long long worker_spawns;
    unsigned long long worker_failures;
};

struct qmev_capture *qmev_capture_new(const struct qmev_capture_seams *seams);
void qmev_capture_free(struct qmev_capture *c);

/*
 * Observation entry points. Each returns true when an observation packet was
 * actually enqueued (i.e. the identity was trusted and a worker was running).
 * A false return is not an error: e.g. a connected identity that arrives
 * while the worker is down is replayed once it (re)starts.
 */
bool qmev_capture_observe_connected(
    struct qmev_capture *c, const char *vmid, pid_t pid, const char *starttime
);
/* `event` is the QMP event name; `full_event` is the complete received object. */
bool qmev_capture_observe_event(
    struct qmev_capture *c, const char *vmid, const char *event, struct json_object *full_event
);
bool qmev_capture_observe_disconnected(struct qmev_capture *c, const char *vmid);
bool qmev_capture_observe_backup(struct qmev_capture *c, const char *vmid, bool active);

/* Current generation for a vmid, 0 if the identity is unknown. */
uint64_t qmev_capture_generation(const struct qmev_capture *c, const char *vmid);

/* fds to watch in the daemon's epoll set; -1 when absent. */
int qmev_capture_worker_fd(const struct qmev_capture *c);
int qmev_capture_worker_pidfd(const struct qmev_capture *c);

/*
 * Register/unregister the worker-visible fds in the daemon's epoll set.
 *
 * The module owns private dup()s of its volatile endpoint fds and registers
 * only those. A dup's number is never handed back to the allocator while it is
 * registered, and it is DELeted before it is ever closed, so a number that has
 * been reused by an unrelated client can never be mistaken for ours. The call
 * is idempotent and cheap when nothing changed; it also toggles EPOLLOUT while
 * an outbound backlog exists so the daemon drains it even with no new events.
 */
void qmev_capture_epoll_sync(struct qmev_capture *c, int epoll_fd);
/* Stable token pointers the daemon compares epoll events against. */
void *qmev_capture_io_token(void);
void *qmev_capture_pidfd_token(void);

/* Private worker socketpair; both ends are CLOEXEC, so no unrelated fork+exec
 * (e.g. the `qm cleanup` helper) can inherit the worker's IPC endpoint. */
int qmev_make_worker_pair(int sv[2]);

/* Read and validate any pending worker -> parent results. */
void qmev_capture_handle_readable(struct qmev_capture *c);
/* Supervise the worker: liveness, bounded restart/backoff, queue flush. */
void qmev_capture_tick(struct qmev_capture *c);
/* Bounded epoll timeout contribution; -1 means "no opinion". */
int qmev_capture_wait_timeout_ms(const struct qmev_capture *c);

void qmev_capture_get_stats(const struct qmev_capture *c, struct qmev_capture_stats *out);

/* Close every fd >= first_fd (used in the child before exec). */
void qmev_close_fds_from(int first_fd);

/*
 * Arrange for the calling (child) process to die with its parent: arm
 * PR_SET_PDEATHSIG(SIGTERM) and re-check the parent to close the fork/PDEATHSIG
 * race. Returns 0 when still a child of `parent_pid`, 1 when the parent is
 * already gone (caller must _exit), negative on prctl failure.
 */
int qmev_arm_child_lifetime(pid_t parent_pid);

/* Parse /proc/<pid>/stat field 22 (starttime). Returns 0 on success. */
int qmev_read_starttime(pid_t pid, char *out, size_t outlen);

#endif /* QMEVENTD_CAPTURE_H */
