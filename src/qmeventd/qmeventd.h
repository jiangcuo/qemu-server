// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    Copyright (C) 2018 - 2021 Proxmox Server Solutions GmbH

    Author: Dominik Csapak <d.csapak@proxmox.com>
    Author: Stefan Reiter <s.reiter@proxmox.com>
*/

#include <sys/syscall.h>
#include <time.h>

#include "qmeventd-log.h"

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

typedef enum {
    CLIENT_NONE,
    CLIENT_QEMU,
    CLIENT_VZDUMP
} ClientType;

typedef enum {
    STATE_HANDSHAKE,
    STATE_IDLE,
    STATE_EXPECT_STATUS_RESP,
    STATE_TERMINATING
} ClientState;

struct Client {
    char buf[4096];
    unsigned int buflen;

    int fd;
    pid_t pid;
    int pidfd;
    time_t timeout;

    ClientType type;
    ClientState state;

    /* protocol error accounting: the first occurrence is logged, repeats are
     * suppressed and reported in bounded summaries (one per threshold and once
     * on close). 64-bit so a hostile peer cannot wrap the counter. */
    unsigned long long proto_errors;
    unsigned long long proto_suppressed;
    time_t proto_first; /* first suppressed error, epoch seconds */
    time_t proto_last;  /* most recent suppressed error, epoch seconds */
    const char *proto_source; /* source= field used for the throttle summary */

    /* per-connection storm control for whitelisted QMP events: at most
     * LOG_STORM_BUDGET records per LOG_STORM_WINDOW is emitted; the rest are
     * suppressed and summarised, so one VM cannot flood the whole journal */
    unsigned long long storm_count;
    unsigned long long storm_suppressed;
    time_t storm_window_start;
    time_t storm_first;
    time_t storm_last;
    char storm_last_event[32];

    // only relevant for type=CLIENT_QEMU
    struct {
        char vmid[16];
        unsigned short graceful;
        unsigned short guest;
        bool term_check_queued;
        bool backup;
        char last_status[16];   /* last query-status string, log dedup only */
        bool term_deferred;     /* termination deferred by backup guard, log dedup only */
    } qemu;

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
