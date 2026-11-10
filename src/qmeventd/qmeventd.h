// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    Copyright (C) 2018 - 2021 Proxmox Server Solutions GmbH

    Author: Dominik Csapak <d.csapak@proxmox.com>
    Author: Stefan Reiter <s.reiter@proxmox.com>
*/

#include <glib.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>

#include "qmeventd-monitor.h"

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif

#define VERBOSE_PRINT(...)                                                                         \
    do {                                                                                           \
        if (verbose) {                                                                             \
            printf(__VA_ARGS__);                                                                   \
            fflush(stdout);                                                                        \
        }                                                                                          \
    } while (0)

static inline void log_neg(int errval, const char *msg) {
    if (errval < 0) {
        perror(msg);
    }
}

static inline void bail_neg(int errval, const char *msg) {
    if (errval < 0) {
        perror(msg);
        exit(EXIT_FAILURE);
    }
}

static inline int pidfd_open(pid_t pid, unsigned int flags) {
    return syscall(__NR_pidfd_open, pid, flags);
}

static inline int pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags) {
    return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

// first member of every structure registered in epoll
typedef enum {
    EP_LISTEN = 1,
    EP_CLIENT,
    EP_TIMER,
    EP_PROBE,
    EP_DISPATCH
} EpollKind;

typedef enum {
    CLIENT_NONE,
    CLIENT_QEMU,
    CLIENT_VZDUMP,
    CLIENT_SUBSCRIBER, // receives every event as one JSON line
    CLIENT_CONTROL     // sent inject/configure/query requests
} ClientType;

typedef enum {
    STATE_HANDSHAKE,
    STATE_IDLE,
    STATE_EXPECT_STATUS_RESP,
    STATE_TERMINATING
} ClientState;

struct Probe;

struct Client {
    EpollKind ep_kind;
    // large enough for monitor replies, e.g. query-blockstats of many disks
    char buf[64 * 1024];
    unsigned int buflen;

    int fd;
    pid_t pid;
    uid_t uid;
    int pidfd;
    time_t timeout;

    ClientType type;
    ClientState state;

    // only relevant for type=CLIENT_QEMU
    struct {
        char vmid[16];
        unsigned short graceful;
        unsigned short guest;
        bool term_check_queued;
        bool backup;
        bool reconnect; // QEMU was already running when qmeventd started
        struct VmMon mon;
        struct Probe *probe;
        // tagged QMP requests in flight, answered by id
        bool req_chardev;
        bool req_blockstats;
        uint64_t req_chardev_since;
        uint64_t req_blockstats_since;
        // event storm limit for journal and subscribers
        uint64_t ev_window_start;
        unsigned ev_count;
        unsigned long long ev_suppressed;
    } qemu;

    // only relevant for CLIENT_SUBSCRIBER/CLIENT_CONTROL: pending output
    GString *out;
    bool out_armed;

    // set when the client must be removed once the current handler returns
    bool dead;

    // only relevant for type=CLIENT_VZDUMP
    struct {
        // vmid of referenced backup
        char vmid[16];
    } vzdump;
};

void handle_qmp_handshake(struct Client *client);
void handle_qmp_event(struct Client *client, struct json_object *obj);
void handle_qmp_return(struct Client *client, struct json_object *data, bool error);
void handle_vzdump_handshake(struct Client *client, struct json_object *data);
void handle_client(struct Client *client);
void add_new_client(int client_fd);
void cleanup_client(struct Client *client);
void terminate_client(struct Client *client);
void terminate_check(struct Client *client);

// `qm event` runs of one VM: strictly one after the other, in event order.
// Keyed by vmid, it outlives the QEMU client so EXITED is still delivered.
struct DispatchQueue {
    EpollKind ep_kind;
    char vmid[16];
    GQueue *pending; // char * argv-ready "EVENT\0JSON" pairs, see dispatch_event()
    pid_t child;
    int pidfd; // registered in epoll while a child runs, -1 otherwise
    uint64_t deadline;
    uint64_t window_start;
    unsigned window_count;
    bool overflow_logged;
};

// guest agent probe of one VM, registered in epoll while connected
struct Probe {
    EpollKind ep_kind;
    struct Client *vm;
    int fd;
    uint64_t deadline;
    char buf[1024];
    size_t len;
};
