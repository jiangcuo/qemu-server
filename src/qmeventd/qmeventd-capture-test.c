// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    Focused unit tests for the qmeventd capture bridge (qmeventd-capture.c).

    The module is compiled into this translation unit so that its seams can be
    driven directly. No real qmeventd worker is ever spawned: spawn, signal,
    clock and journal output are all injected. The private worker endpoint is a
    real SOCK_SEQPACKET socketpair so packet framing is exercised for real.
*/

#define _GNU_SOURCE
#include "qmeventd-capture.c"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>

/* ------------------------------------------------------------------ */
/* injected seams                                                     */
/* ------------------------------------------------------------------ */

static int g_sv[2] = {-1, -1}; /* fake worker endpoint pair */
static int spawn_calls = 0;
static int spawn_result = 0; /* 0 ok, <0 fail */
static pid_t spawn_pid = 4242;
static int fake_sndbuf = 0; /* >0: shrink the worker socket send buffer */

static int signal_calls = 0;
static int signal_last_pidfd = -1;
static pid_t signal_last_pid = -1;
static int signal_last_sig = 0;

static int open_pidfd_calls = 0;
/* -2: return a fresh dup() of a persistent source fd (a normal, supervised
 * worker); -1: pretend pidfd_open() failed; >=0: return exactly this fd */
static int fake_pidfd_val = -2;
static int g_pidfd_src = -1; /* persistent fd the fake pidfds are dup'd from */
static int g_pidfd_wr = -1;
static int probe_supported = 1;

static uint64_t fake_now = 1000;

static struct {
    char vmid[16];
    pid_t qemu_pid;
    pid_t peer_pid;
    QLogLevel level;
    char source[32];
    char event[64];
    char payload[512];
} logs[128];
static int log_count = 0;

static int seam_spawn(void *ud, int *parent_fd_out, pid_t *pid_out) {
    (void)ud;
    spawn_calls++;
    if (spawn_result != 0) {
        return spawn_result;
    }
    if (g_sv[1] >= 0) {
        close(g_sv[1]);
    }
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, g_sv) != 0) {
        abort();
    }
    if (fake_sndbuf > 0) {
        setsockopt(g_sv[0], SOL_SOCKET, SO_SNDBUF, &fake_sndbuf, sizeof(fake_sndbuf));
    }
    *parent_fd_out = g_sv[0];
    *pid_out = spawn_pid;
    return 0;
}

static void seam_log(
    void *ud,
    const char *vmid,
    pid_t qpid,
    pid_t ppid,
    QLogLevel level,
    const char *source,
    const char *event,
    struct json_object *payload
) {
    int i;
    (void)ud;
    if (log_count >= (int)(sizeof(logs) / sizeof(logs[0]))) {
        return;
    }
    i = log_count++;
    snprintf(logs[i].vmid, sizeof(logs[i].vmid), "%s", vmid ? vmid : "-");
    logs[i].qemu_pid = qpid;
    logs[i].peer_pid = ppid;
    logs[i].level = level;
    snprintf(logs[i].source, sizeof(logs[i].source), "%s", source ? source : "-");
    snprintf(logs[i].event, sizeof(logs[i].event), "%s", event ? event : "-");
    logs[i].payload[0] = '\0';
    if (payload) {
        snprintf(
            logs[i].payload, sizeof(logs[i].payload), "%s",
            json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PLAIN)
        );
    }
}

static int seam_signal(void *ud, int pidfd, pid_t pid, int sig) {
    (void)ud;
    signal_calls++;
    signal_last_pidfd = pidfd;
    signal_last_pid = pid;
    signal_last_sig = sig;
    return 0;
}

static int seam_open_pidfd(void *ud, pid_t pid) {
    (void)ud;
    (void)pid;
    open_pidfd_calls++;
    if (fake_pidfd_val == -1) {
        return -1; /* simulate pidfd_open() failure for this worker */
    }
    if (fake_pidfd_val >= 0) {
        return fake_pidfd_val;
    }
    return dup(g_pidfd_src);
}

static int seam_probe_pidfd(void *ud) {
    (void)ud;
    if (!probe_supported) {
        return -1; /* simulate an old kernel without pidfd_open() */
    }
    return dup(g_pidfd_src);
}

static uint64_t seam_now(void *ud) {
    (void)ud;
    return fake_now;
}

static struct qmev_capture_seams make_seams(void) {
    struct qmev_capture_seams s;
    memset(&s, 0, sizeof(s));
    s.spawn = seam_spawn;
    s.log = seam_log;
    s.now_ms = seam_now;
    s.signal_worker = seam_signal;
    s.open_pidfd = seam_open_pidfd;
    s.pidfd_probe = seam_probe_pidfd;
    return s;
}

/* ------------------------------------------------------------------ */
/* harness                                                            */
/* ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_failed = 0;

static void reset_seams(void) {
    spawn_calls = 0;
    spawn_result = 0;
    spawn_pid = 4242;
    fake_sndbuf = 0;
    signal_calls = 0;
    open_pidfd_calls = 0;
    fake_pidfd_val = -2;
    probe_supported = 1;
    signal_last_pidfd = -1;
    signal_last_pid = -1;
    signal_last_sig = 0;
    fake_now = 1000;
    log_count = 0;
}

static struct qmev_capture *mk(void) {
    struct qmev_capture_seams s = make_seams();
    if (g_sv[0] >= 0) {
        close(g_sv[0]);
        g_sv[0] = -1;
    }
    if (g_sv[1] >= 0) {
        close(g_sv[1]);
        g_sv[1] = -1;
    }
    reset_seams();
    return qmev_capture_new(&s);
}

/* free the module and forget the fd it owned */
static void fini(struct qmev_capture *c) {
    qmev_capture_free(c);
    g_sv[0] = -1;
}

static size_t recv_pkt(char *out, size_t cap) {
    ssize_t n = recv(g_sv[1], out, cap - 1, MSG_DONTWAIT);
    if (n < 0) {
        out[0] = '\0';
        return 0;
    }
    out[n] = '\0';
    return (size_t)n;
}

static struct json_object *recv_json(char *scratch, size_t cap) {
    size_t n = recv_pkt(scratch, cap);
    if (n == 0) {
        return NULL;
    }
    return json_tokener_parse(scratch);
}

static const char *jstr(struct json_object *o, const char *key) {
    struct json_object *v;
    if (!o || !json_object_object_get_ex(o, key, &v)) {
        return NULL;
    }
    return json_object_get_string(v);
}

static long long jint(struct json_object *o, const char *key) {
    struct json_object *v;
    if (!o || !json_object_object_get_ex(o, key, &v)) {
        return -999;
    }
    return (long long)json_object_get_int64(v);
}

#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);                          \
            tests_failed++;                                                                        \
            return;                                                                                \
        }                                                                                          \
    } while (0)

/* ------------------------------------------------------------------ */
/* group 1: connected identity, generation, packet shape              */
/* ------------------------------------------------------------------ */

static void test_connected_packet_shape(void) {
    struct qmev_capture *c = mk();
    char scratch[8192];
    struct json_object *o;

    CHECK(qmev_capture_observe_connected(c, "111", 1234, "987654"),
          "a trusted connected identity must enqueue an observation");
    CHECK(spawn_calls == 1, "the first observation must lazily start the worker");
    CHECK(qmev_capture_worker_fd(c) >= 0, "a running worker exposes its fd");

    o = recv_json(scratch, sizeof(scratch));
    CHECK(o != NULL, "the connected packet must be valid JSON");
    CHECK(!strcmp(jstr(o, "op"), "observe"), "op must be observe");
    CHECK(!strcmp(jstr(o, "kind"), "connected"), "kind must be connected");
    CHECK(jint(o, "vmid") == 111, "vmid must be a positive integer");
    CHECK(jint(o, "pid") == 1234, "pid must be a positive integer");
    CHECK(jstr(o, "starttime") && !strcmp(jstr(o, "starttime"), "987654"),
          "starttime must be the decimal string");
    CHECK(jint(o, "generation") == 1, "the fresh identity gets generation 1");
    CHECK(!jstr(o, "event"), "connected must not carry an event field");
    json_object_put(o);
    fini(c);
}

static void test_new_connection_advances_generation(void) {
    struct qmev_capture *c = mk();
    char scratch[8192];
    struct json_object *o;

    qmev_capture_observe_connected(c, "111", 1234, "10");
    qmev_capture_observe_connected(c, "222", 5678, "20");
    qmev_capture_observe_connected(c, "111", 9999, "30"); /* reconnect */

    CHECK(qmev_capture_generation(c, "111") == 3, "a reconnect gets a new generation");
    CHECK(qmev_capture_generation(c, "222") == 2, "an unrelated VM keeps its own generation");
    CHECK(qmev_capture_generation(c, "999") == 0, "an unknown vmid has no generation");

    /* the reconnect packet must carry the advanced generation and new pid */
    (void)recv_pkt(scratch, sizeof(scratch));
    (void)recv_pkt(scratch, sizeof(scratch));
    o = recv_json(scratch, sizeof(scratch));
    CHECK(o && jint(o, "generation") == 3, "the reconnect observation carries generation 3");
    CHECK(o && jint(o, "pid") == 9999, "the reconnect observation carries the new pid");
    json_object_put(o);
    fini(c);
}

static void test_untrusted_connected_identity_is_rejected(void) {
    struct qmev_capture *c = mk();
    char scratch[8192];

    CHECK(!qmev_capture_observe_connected(c, "abc", 1234, "10"), "a non-numeric vmid is rejected");
    CHECK(!qmev_capture_observe_connected(c, "111", 0, "10"), "a non-positive pid is rejected");
    CHECK(!qmev_capture_observe_connected(c, "111", 1234, "x"), "a non-numeric starttime is rejected");
    CHECK(!qmev_capture_observe_connected(c, "111", 1234, ""), "an empty starttime is rejected");
    CHECK(qmev_capture_generation(c, "111") == 0, "no identity must be stored for rejected input");
    CHECK(spawn_calls == 0, "no worker may be started for untrusted input");
    CHECK(recv_pkt(scratch, sizeof(scratch)) == 0, "nothing may be forwarded for untrusted input");
    fini(c);
}

/* ------------------------------------------------------------------ */
/* group 2: worker -> parent result validation                        */
/* ------------------------------------------------------------------ */

/* play the worker: push one packet on the child end of the private pair */
static void worker_send(const char *s) {
    if (send(g_sv[1], s, strlen(s), 0) < 0) {
        abort();
    }
}

static void test_valid_worker_result_is_logged(void) {
    struct qmev_capture *c = mk();
    struct qmev_capture_stats st = {0};

    qmev_capture_observe_connected(c, "111", 1234, "10");
    log_count = 0; /* ignore the parent->worker traffic, we look at seam logs */
    worker_send(
        "{\"op\":\"log\",\"vmid\":111,\"pid\":1234,\"starttime\":\"10\","
        "\"generation\":1,\"level\":\"warning\",\"source\":\"qga\","
        "\"event\":\"HEARTBEAT_LOST\",\"payload\":{\"a\":1}}"
    );
    qmev_capture_handle_readable(c);

    CHECK(log_count == 1, "a valid worker result must be logged exactly once");
    CHECK(!strcmp(logs[0].vmid, "111"), "vmid comes from the trusted identity");
    CHECK(logs[0].qemu_pid == 1234, "qemu_pid comes from the trusted identity");
    CHECK(logs[0].level == QLOG_WARNING, "level mapped from the packet");
    CHECK(!strcmp(logs[0].source, "qga"), "source preserved");
    CHECK(!strcmp(logs[0].event, "HEARTBEAT_LOST"), "event preserved");
    CHECK(strstr(logs[0].payload, "\"a\":1") != NULL, "payload preserved");
    qmev_capture_get_stats(c, &st);
    CHECK(st.results_accepted == 1, "accepted counted");
    fini(c);
}

static void test_stale_generation_result_is_dropped(void) {
    struct qmev_capture *c = mk();
    struct qmev_capture_stats st = {0};

    qmev_capture_observe_connected(c, "111", 1234, "10"); /* generation 1 */
    qmev_capture_observe_connected(c, "111", 5555, "20"); /* generation 2 (reconnect) */
    log_count = 0;
    worker_send(
        "{\"op\":\"log\",\"vmid\":111,\"pid\":1234,\"starttime\":\"10\","
        "\"generation\":1,\"level\":\"info\",\"source\":\"capture\","
        "\"event\":\"SCREENSHOT_SAVED\"}"
    );
    qmev_capture_handle_readable(c);

    CHECK(log_count == 0, "a result for an old generation must never attach to the new VM");
    qmev_capture_get_stats(c, &st);
    CHECK(st.results_stale == 1, "stale result counted");
    fini(c);
}

static void test_mismatched_identity_result_is_dropped(void) {
    struct qmev_capture *c = mk();
    struct qmev_capture_stats st = {0};

    qmev_capture_observe_connected(c, "111", 1234, "10");
    log_count = 0;
    worker_send(
        "{\"op\":\"log\",\"vmid\":111,\"pid\":9999,\"starttime\":\"10\","
        "\"generation\":1,\"level\":\"info\",\"source\":\"qga\",\"event\":\"HEARTBEAT_READY\"}"
    );
    worker_send(
        "{\"op\":\"log\",\"vmid\":111,\"pid\":1234,\"starttime\":\"99\","
        "\"generation\":1,\"level\":\"info\",\"source\":\"qga\",\"event\":\"HEARTBEAT_READY\"}"
    );
    worker_send(
        "{\"op\":\"log\",\"vmid\":999,\"pid\":1234,\"starttime\":\"10\","
        "\"generation\":1,\"level\":\"info\",\"source\":\"qga\",\"event\":\"HEARTBEAT_READY\"}"
    );
    qmev_capture_handle_readable(c);

    CHECK(log_count == 0, "a result whose identity does not match must be dropped");
    qmev_capture_get_stats(c, &st);
    CHECK(st.results_stale == 3, "each mismatching result is counted as stale");
    fini(c);
}

static void test_unsafe_source_event_or_level_is_rejected(void) {
    struct qmev_capture *c = mk();
    struct qmev_capture_stats st = {0};

    qmev_capture_observe_connected(c, "111", 1234, "10");
    log_count = 0;
    /* source outside {qga,capture} */
    worker_send(
        "{\"op\":\"log\",\"vmid\":111,\"pid\":1234,\"starttime\":\"10\","
        "\"generation\":1,\"level\":\"info\",\"source\":\"shell\",\"event\":\"HEARTBEAT_READY\"}"
    );
    /* event outside the allowed vocabulary */
    worker_send(
        "{\"op\":\"log\",\"vmid\":111,\"pid\":1234,\"starttime\":\"10\","
        "\"generation\":1,\"level\":\"info\",\"source\":\"capture\",\"event\":\"RUN_SHELL\"}"
    );
    /* level outside {info,warning,error} */
    worker_send(
        "{\"op\":\"log\",\"vmid\":111,\"pid\":1234,\"starttime\":\"10\","
        "\"generation\":1,\"level\":\"critical\",\"source\":\"capture\","
        "\"event\":\"SCREENSHOT_FAILED\"}"
    );
    qmev_capture_handle_readable(c);

    CHECK(log_count == 0, "unsafe source/event/level must not reach the journal");
    qmev_capture_get_stats(c, &st);
    CHECK(st.results_invalid == 3, "each rejected result is counted as invalid");
    CHECK(st.results_accepted == 0, "nothing was accepted");
    fini(c);
}

static void test_worker_cannot_command_the_vm(void) {
    struct qmev_capture *c = mk();
    struct qmev_capture_stats st = {0};

    qmev_capture_observe_connected(c, "111", 1234, "10");
    log_count = 0;
    /* a packet that tries to look like a control request is not a log result */
    worker_send("{\"op\":\"quit\",\"vmid\":111,\"pid\":1234,\"generation\":1}");
    worker_send("{\"op\":\"reset\",\"vmid\":111,\"pid\":1234,\"generation\":1}");
    qmev_capture_handle_readable(c);

    CHECK(log_count == 0, "non-log ops must never be logged");
    CHECK(signal_calls == 0, "the worker may never make qmeventd signal a VM");
    qmev_capture_get_stats(c, &st);
    CHECK(st.results_invalid == 2, "non-log ops are rejected as invalid");
    fini(c);
}

static void test_malformed_worker_packet_is_rejected(void) {
    struct qmev_capture *c = mk();
    struct qmev_capture_stats st = {0};

    qmev_capture_observe_connected(c, "111", 1234, "10");
    log_count = 0;
    worker_send("not json");
    worker_send("{\"op\":\"log\"");
    qmev_capture_handle_readable(c);

    CHECK(log_count == 0, "malformed packets must not reach the journal");
    qmev_capture_get_stats(c, &st);
    CHECK(st.results_invalid == 2, "malformed packets are counted as invalid");
    fini(c);
}

/* ------------------------------------------------------------------ */
/* group 3: lifecycle / panic event forwarding, RESET generation      */
/* ------------------------------------------------------------------ */

static struct json_object *mj(const char *s) {
    struct json_object *o = json_tokener_parse(s);
    if (!o) {
        fprintf(stderr, "bad test json: %s\n", s);
        abort();
    }
    return o;
}

static void test_lifecycle_event_is_forwarded(void) {
    struct qmev_capture *c = mk();
    char scratch[8192];
    struct json_object *o;
    struct json_object *full = mj(
        "{\"event\":\"STOP\",\"data\":{\"x\":1},\"timestamp\":{\"seconds\":7}}"
    );
    struct json_object *ev;

    qmev_capture_observe_connected(c, "111", 1234, "10");
    (void)recv_pkt(scratch, sizeof(scratch)); /* drop the connected packet */

    CHECK(qmev_capture_observe_event(c, "111", "STOP", full), "a lifecycle event must be forwarded");
    o = recv_json(scratch, sizeof(scratch));
    CHECK(o != NULL, "an event packet must be sent");
    CHECK(!strcmp(jstr(o, "op"), "observe") && !strcmp(jstr(o, "kind"), "event"), "op/kind");
    CHECK(jint(o, "vmid") == 111 && jint(o, "pid") == 1234, "identity carried");
    CHECK(jint(o, "generation") == 1, "generation carried");
    CHECK(json_object_object_get_ex(o, "event", &ev), "the full event object must be present");
    CHECK(!strcmp(jstr(ev, "event"), "STOP"), "the raw event name is preserved");
    CHECK(json_object_object_get_ex(ev, "data", &ev) && jint(ev, "x") == 1,
          "the event data is preserved unchanged");
    json_object_put(o);
    json_object_put(full);
    fini(c);
}

static void test_reset_advances_generation(void) {
    struct qmev_capture *c = mk();
    char scratch[8192];
    struct json_object *o;
    struct json_object *reset = mj("{\"event\":\"RESET\"}");

    qmev_capture_observe_connected(c, "111", 1234, "10"); /* generation 1 */
    (void)recv_pkt(scratch, sizeof(scratch));
    CHECK(qmev_capture_observe_event(c, "111", "RESET", reset),
          "RESET must be forwarded");
    CHECK(qmev_capture_generation(c, "111") == 2,
          "a guest RESET advances the generation even with an unchanged PID");
    o = recv_json(scratch, sizeof(scratch));
    CHECK(o && jint(o, "generation") == 2, "the RESET observation carries the new generation");
    CHECK(o && jint(o, "pid") == 1234, "the QEMU PID is unchanged");
    json_object_put(o);
    json_object_put(reset);
    fini(c);
}

static void test_non_whitelisted_event_is_not_forwarded(void) {
    struct qmev_capture *c = mk();
    char scratch[8192];
    struct json_object *balloon = mj("{\"event\":\"BALLOON_CHANGE\",\"data\":{\"actual\":1}}");

    qmev_capture_observe_connected(c, "111", 1234, "10");
    (void)recv_pkt(scratch, sizeof(scratch));

    CHECK(!qmev_capture_observe_event(c, "111", "BALLOON_CHANGE", balloon),
          "a non-lifecycle event must not be forwarded");
    CHECK(recv_pkt(scratch, sizeof(scratch)) == 0, "no packet may be sent");
    CHECK(qmev_capture_generation(c, "111") == 1, "a non-RESET event does not touch the generation");
    json_object_put(balloon);
    fini(c);
}

static void test_event_for_unassociated_client_is_dropped(void) {
    struct qmev_capture *c = mk();
    char scratch[8192];
    struct json_object *stop = mj("{\"event\":\"STOP\"}");

    /* no connected identity yet: an event must never create one */
    CHECK(!qmev_capture_observe_event(c, "999", "STOP", stop),
          "an event for an unassociated client is dropped");
    CHECK(spawn_calls == 0, "no worker may be started for an unassociated client");
    CHECK(recv_pkt(scratch, sizeof(scratch)) == 0, "nothing may be forwarded");
    json_object_put(stop);
    fini(c);
}

static void test_panic_events_are_forwarded_with_full_object(void) {
    const char *names[] = {"GUEST_PANICKED", "GUEST_CRASHLOADED"};
    size_t i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        struct qmev_capture *c = mk();
        char in[128];
        char scratch[8192];
        struct json_object *o;
        struct json_object *ev;
        struct json_object *full;

        qmev_capture_observe_connected(c, "111", 1234, "10");
        (void)recv_pkt(scratch, sizeof(scratch));
        snprintf(in, sizeof(in), "{\"event\":\"%s\",\"data\":{\"reason\":\"r\"}}", names[i]);
        full = mj(in);
        CHECK(qmev_capture_observe_event(c, "111", names[i], full), "panic event must be forwarded");
        o = recv_json(scratch, sizeof(scratch));
        CHECK(o && json_object_object_get_ex(o, "event", &ev), "full event present");
        CHECK(ev && !strcmp(jstr(ev, "event"), names[i]), "event name preserved");
        CHECK(ev && json_object_object_get_ex(ev, "data", &ev) && !strcmp(jstr(ev, "reason"), "r"),
              "event data preserved");
        json_object_put(o);
        json_object_put(full);
        fini(c);
    }
}

static void test_migration_event_is_forwarded(void) {
    struct qmev_capture *c = mk();
    char scratch[8192];
    struct json_object *mig = mj("{\"event\":\"MIGRATION\",\"data\":{\"status\":\"active\"}}");

    qmev_capture_observe_connected(c, "111", 1234, "10");
    (void)recv_pkt(scratch, sizeof(scratch));
    CHECK(qmev_capture_observe_event(c, "111", "MIGRATION", mig),
          "a relevant migration state must be forwarded");
    json_object_put(mig);
    fini(c);
}

/* ------------------------------------------------------------------ */
/* group 4: disconnected + backup observation (mapped QEMU identity)  */
/* ------------------------------------------------------------------ */

static void test_disconnected_is_forwarded_then_identity_forgotten(void) {
    struct qmev_capture *c = mk();
    struct qmev_capture_stats st = {0};
    char scratch[8192];
    struct json_object *o;

    qmev_capture_observe_connected(c, "111", 1234, "10");
    (void)recv_pkt(scratch, sizeof(scratch));
    CHECK(qmev_capture_observe_disconnected(c, "111"), "disconnected must be forwarded");
    o = recv_json(scratch, sizeof(scratch));
    CHECK(o && !strcmp(jstr(o, "kind"), "disconnected"), "kind disconnected");
    CHECK(o && jint(o, "pid") == 1234 && jint(o, "generation") == 1, "identity carried");
    json_object_put(o);

    CHECK(qmev_capture_generation(c, "111") == 0, "the identity must be forgotten on disconnect");
    CHECK(!qmev_capture_observe_disconnected(c, "111"), "a repeated disconnect is a no-op");

    /* a worker result that arrives after the disconnect must not attach */
    log_count = 0;
    worker_send(
        "{\"op\":\"log\",\"vmid\":111,\"pid\":1234,\"starttime\":\"10\","
        "\"generation\":1,\"level\":\"info\",\"source\":\"capture\",\"event\":\"SCREENSHOT_SAVED\"}"
    );
    qmev_capture_handle_readable(c);
    CHECK(log_count == 0, "a late result must never attach to the gone VM");
    qmev_capture_get_stats(c, &st);
    CHECK(st.results_stale == 1, "the late result is counted as stale");
    fini(c);
}

static void test_backup_observation_maps_to_qemu_identity(void) {
    struct qmev_capture *c = mk();
    char scratch[8192];
    struct json_object *o;

    qmev_capture_observe_connected(c, "111", 1234, "10");
    (void)recv_pkt(scratch, sizeof(scratch));

    CHECK(qmev_capture_observe_backup(c, "111", true), "backup enter must be forwarded");
    o = recv_json(scratch, sizeof(scratch));
    CHECK(o && !strcmp(jstr(o, "kind"), "backup"), "kind backup");
    /* the mapped QEMU identity, never a backup-helper PID */
    CHECK(o && jint(o, "pid") == 1234 && jint(o, "generation") == 1, "mapped QEMU identity");
    CHECK(o && jint(o, "vmid") == 111, "vmid carried");
    {
        struct json_object *b;
        CHECK(json_object_object_get_ex(o, "backup", &b) && json_object_get_boolean(b) == 1,
              "backup=true");
    }
    json_object_put(o);

    CHECK(qmev_capture_observe_backup(c, "111", false), "backup leave must be forwarded");
    o = recv_json(scratch, sizeof(scratch));
    {
        struct json_object *b;
        CHECK(o && json_object_object_get_ex(o, "backup", &b) && json_object_get_boolean(b) == 0,
              "backup=false");
    }
    json_object_put(o);
    fini(c);
}

static void test_backup_for_unknown_vmid_is_dropped(void) {
    struct qmev_capture *c = mk();
    char scratch[8192];

    CHECK(!qmev_capture_observe_backup(c, "999", true),
          "a backup for an unregistered VM must be dropped");
    CHECK(spawn_calls == 0, "no worker may be started for an unregistered VM");
    CHECK(recv_pkt(scratch, sizeof(scratch)) == 0, "nothing may be forwarded");
    fini(c);
}

/* ------------------------------------------------------------------ */
/* group 5: bounded transport (queue, packet size, drop report)       */
/* ------------------------------------------------------------------ */

static int count_seam_event(const char *event) {
    int i, n = 0;
    for (i = 0; i < log_count; i++) {
        if (!strcmp(logs[i].event, event)) {
            n++;
        }
    }
    return n;
}

static void test_queue_is_bounded_and_drops_reported(void) {
    struct qmev_capture *c;
    struct qmev_capture_stats st = {0};
    int i;

    fake_sndbuf = 2048; /* the worker endpoint stops accepting quickly */
    c = mk();
    fake_sndbuf = 2048;
    for (i = 0; i < 1400; i++) {
        qmev_capture_observe_connected(c, "111", 1234, "10");
    }
    qmev_capture_get_stats(c, &st);
    CHECK(st.observations_sent >= 1024, "the bounded window must be a real number of packets");
    CHECK(st.observations_dropped >= 1, "a full queue must drop rather than grow without bound");
    CHECK(count_seam_event("CAPTURE_IPC_DROPPED") == 1,
          "the loss must be reported exactly once per window, not silently");
    fini(c);
}

static void test_oversized_observation_packet_is_refused(void) {
    struct qmev_capture *c = mk();
    struct qmev_capture_stats st = {0};
    char scratch[8192];
    char *big = malloc(70000);
    struct json_object *full = json_object_new_object();
    struct json_object *data = json_object_new_object();

    memset(big, 'a', 70000);
    json_object_object_add(full, "event", json_object_new_string("STOP"));
    json_object_object_add(data, "big", json_object_new_string_len(big, 70000));
    json_object_object_add(full, "data", data);

    qmev_capture_observe_connected(c, "111", 1234, "10");
    (void)recv_pkt(scratch, sizeof(scratch)); /* drop the connected packet */
    CHECK(!qmev_capture_observe_event(c, "111", "STOP", full),
          "an observation larger than the packet bound must be refused");
    qmev_capture_get_stats(c, &st);
    CHECK(st.packets_too_large == 1, "the oversized packet is counted");
    CHECK(recv_pkt(scratch, sizeof(scratch)) == 0, "nothing oversized may be sent");
    json_object_put(full);
    free(big);
    fini(c);
}

static void test_oversized_worker_packet_is_rejected(void) {
    struct qmev_capture *c = mk();
    struct qmev_capture_stats st = {0};
    char *big = malloc(70000 + 64);
    int n;

    qmev_capture_observe_connected(c, "111", 1234, "10");
    log_count = 0;
    n = snprintf(
        big, 70000 + 64,
        "{\"op\":\"log\",\"vmid\":111,\"pid\":1234,\"starttime\":\"10\",\"generation\":1,"
        "\"level\":\"info\",\"source\":\"capture\",\"event\":\"SCREENSHOT_SKIPPED\",\"payload\":{"
        "\"pad\":\""
    );
    memset(big + n, 'a', 70000 - n);
    strcpy(big + 70000, "}}");
    if (send(g_sv[1], big, 70002, 0) < 0) {
        abort();
    }
    qmev_capture_handle_readable(c);
    CHECK(log_count == 0, "an oversized worker packet must not be logged");
    qmev_capture_get_stats(c, &st);
    CHECK(st.results_invalid == 1, "an oversized worker packet is counted as invalid");
    free(big);
    fini(c);
}

/* ------------------------------------------------------------------ */
/* group 6: worker supervision (liveness, restart/replay, backoff)    */
/* ------------------------------------------------------------------ */

static void test_worker_restart_replays_known_vms_with_latest_generation(void) {
    struct qmev_capture *c = mk();
    struct json_object *reset = mj("{\"event\":\"RESET\"}");
    char scratch[8192];
    struct json_object *o;
    int seen111 = 0, seen222 = 0;
    long long goodd;
    int i;

    qmev_capture_observe_connected(c, "111", 1234, "10"); /* generation 1 */
    qmev_capture_observe_connected(c, "222", 5678, "20"); /* generation 2 */
    qmev_capture_observe_event(c, "111", "RESET", reset); /* generation 3 */
    json_object_put(reset);
    while (recv_pkt(scratch, sizeof(scratch)) > 0) {
        ; /* drain the initial connected/event packets */
    }

    /* the worker endpoint dies */
    close(g_sv[1]);
    g_sv[1] = -1;
    qmev_capture_tick(c); /* poll detects EOF and supervises */
    CHECK(qmev_capture_worker_fd(c) == -1, "a dead worker's fd must be released");

    fake_now += 60000; /* move past the bounded backoff */
    qmev_capture_tick(c);
    CHECK(spawn_calls == 2, "the worker must be restarted after the backoff");
    CHECK(qmev_capture_worker_fd(c) >= 0, "the new worker exposes a fresh fd");

    for (i = 0; i < 4; i++) {
        o = recv_json(scratch, sizeof(scratch));
        if (!o) {
            break;
        }
        if (!strcmp(jstr(o, "kind"), "connected") && jint(o, "vmid") == 111) {
            seen111 = 1;
            goodd = jint(o, "generation");
            CHECK(goodd == 3, "111 must be replayed with its LATEST generation");
        }
        if (!strcmp(jstr(o, "kind"), "connected") && jint(o, "vmid") == 222) {
            seen222 = 1;
            CHECK(jint(o, "generation") == 2, "222 must be replayed with its own generation");
        }
        json_object_put(o);
    }
    CHECK(seen111 && seen222, "every known VM identity must be replayed after a restart");
    fini(c);
}

static void test_spawn_failure_backs_off_and_reports_once(void) {
    struct qmev_capture *c = mk();
    struct qmev_capture_stats st = {0};
    int i;

    spawn_result = -1;
    CHECK(!qmev_capture_observe_connected(c, "111", 1234, "10"),
          "an observation while the worker is unavailable is not forwarded");
    CHECK(spawn_calls == 1, "the worker is attempted once");

    for (i = 0; i < 50; i++) {
        qmev_capture_observe_connected(c, "111", 1234, "10"); /* same instant */
    }
    CHECK(spawn_calls == 1, "a missing worker must never spin the daemon");
    CHECK(count_seam_event("CAPTURE_WORKER_UNAVAILABLE") == 1,
          "unavailability is reported once, not per attempt");

    fake_now += 60000; /* past any bounded backoff */
    qmev_capture_observe_connected(c, "111", 1234, "10");
    CHECK(spawn_calls == 2, "a bounded retry happens after the backoff");
    CHECK(count_seam_event("CAPTURE_WORKER_UNAVAILABLE") == 1,
          "the backoff must not flood the journal");
    qmev_capture_get_stats(c, &st);
    CHECK(st.worker_failures == 2, "each failed attempt is counted");
    fini(c);
}

static void test_worker_liveness_and_bounded_timeout(void) {
    struct qmev_capture *c = mk();

    CHECK(qmev_capture_worker_fd(c) == -1 && qmev_capture_worker_pidfd(c) == -1,
          "no worker is running yet");
    CHECK(qmev_capture_wait_timeout_ms(c) == -1, "an idle module has no timing opinion");

    qmev_capture_observe_connected(c, "111", 1234, "10");
    CHECK(qmev_capture_worker_fd(c) >= 0, "a running worker exposes a watchable fd");
    CHECK(qmev_capture_wait_timeout_ms(c) >= 0 && qmev_capture_wait_timeout_ms(c) <= 1000,
          "the supervision tick is bounded");

    /* the endpoint closing is detected by the tick itself */
    close(g_sv[1]);
    g_sv[1] = -1;
    qmev_capture_tick(c);
    CHECK(qmev_capture_worker_fd(c) == -1, "the tick must notice the closed endpoint");
    CHECK(qmev_capture_wait_timeout_ms(c) >= 0, "a pending restart keeps a bounded tick");
    fini(c);
}

/* ------------------------------------------------------------------ */
/* group 7: child setup helpers + identity reader                     */
/* ------------------------------------------------------------------ */

static void test_worker_path_is_fixed(void) {
    CHECK(!strcmp(QMEV_CAPTURE_WORKER_PATH, "/usr/libexec/qemu-server/qmeventd-worker"),
          "the worker path is a fixed production constant, never an env choice");
}

static void test_arm_child_lifetime(void) {
    int pdsig = 0;
    CHECK(qmev_arm_child_lifetime(getppid()) == 0,
          "a child whose parent is alive arms cleanly");
    prctl(PR_GET_PDEATHSIG, &pdsig);
    CHECK(pdsig == SIGTERM, "PR_SET_PDEATHSIG must be armed with SIGTERM");
    CHECK(qmev_arm_child_lifetime((pid_t)(getppid() + 100000)) == 1,
          "an already-gone parent (fork/PDEATHSIG race) is detected");
}

static void test_close_fds_from_closes_everything_high(void) {
    int status = 0;
    pid_t pid = fork();
    if (pid == 0) {
        int a = open("/dev/null", O_RDONLY);
        int b = (a >= 0) ? dup(a) : -1;
        qmev_close_fds_from(3);
        /* both opened fds (>= 3) must be closed; stdin/stdout/stderr stay */
        if (a < 0 || b < 0) {
            _exit(2);
        }
        if (fcntl(a, F_GETFD) != -1 || fcntl(b, F_GETFD) != -1) {
            _exit(1);
        }
        _exit(0);
    }
    CHECK(pid > 0, "fork failed");
    CHECK(waitpid(pid, &status, 0) == pid, "waitpid failed");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "close_fds_from must close every fd >= the given base");
}

static void test_read_starttime_matches_proc(void) {
    char got[64];
    char line[4096];
    char want[64] = {0};
    FILE *f;
    char *rp;
    int field;
    char *tok;
    char *save = NULL;

    CHECK(qmev_read_starttime(getpid(), got, sizeof(got)) == 0,
          "our own starttime must be readable");
    {
        const char *p;
        for (p = got; *p; p++) {
            CHECK(*p >= '0' && *p <= '9', "starttime is a decimal string");
        }
    }

    f = fopen("/proc/self/stat", "r");
    CHECK(f != NULL, "cannot read /proc/self/stat");
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        CHECK(0, "cannot read stat line");
    }
    fclose(f);
    rp = strrchr(line, ')');
    CHECK(rp != NULL, "no comm terminator");
    /* tokens after ')' : field 3 .. field 22 (starttime) = 20th token */
    for (tok = strtok_r(rp + 1, " ", &save), field = 1; tok; tok = strtok_r(NULL, " ", &save), field++) {
        if (field == 20) {
            snprintf(want, sizeof(want), "%s", tok);
            break;
        }
    }
    CHECK(!strcmp(got, want), "parsed starttime must match field 22 of /proc/self/stat");
}

static void test_read_starttime_missing_pid(void) {
    char got[64];
    CHECK(qmev_read_starttime((pid_t)2000000000, got, sizeof(got)) != 0,
          "a nonexistent pid has no starttime");
}

/* ------------------------------------------------------------------ */
/* group 8: identity-proven worker termination                        */
/* ------------------------------------------------------------------ */

static void test_worker_termination_uses_pidfd_identity(void) {
    struct qmev_capture *c;
    int pfd[2];

    if (pipe(pfd) != 0) {
        abort();
    }
    c = mk();
    fake_pidfd_val = pfd[0]; /* pretend this is the supervised worker's pidfd */
    qmev_capture_observe_connected(c, "111", 1234, "10");
    CHECK(qmev_capture_worker_pidfd(c) == pfd[0], "the worker pidfd must be tracked");
    CHECK(open_pidfd_calls == 1, "the pidfd is opened once for the spawned worker");

    /* the endpoint dies but the process may still linger: terminate it by the
     * identity-proven pidfd, never a bare (reusable) PID */
    close(g_sv[1]);
    g_sv[1] = -1;
    signal_calls = 0;
    qmev_capture_tick(c);
    CHECK(signal_calls == 1, "a lingering worker must be terminated");
    CHECK(signal_last_pidfd == pfd[0], "termination goes through the pidfd");
    CHECK(signal_last_sig == SIGTERM, "termination uses SIGTERM");
    CHECK(qmev_capture_worker_pidfd(c) == -1, "the pidfd is released after termination");

    close(pfd[1]);
    fini(c);
}

/* ------------------------------------------------------------------ */
/* group 9: root-cause regressions (epoll reuse, CLOEXEC, replay,     */
/*          backlog drain, pidfd fail-closed, pairing, recv budget)   */
/* ------------------------------------------------------------------ */

static int epoll_client_token;

/*
 * R4: the daemon's epoll registration must be bound to the registration's
 * lifetime, never to a raw fd number. When a worker dies, its fds are closed
 * and a new client can reuse the number; a later synchronous unregister must
 * never DELETE that reused client.
 */
static void test_epoll_sync_never_deletes_a_reused_fd(void) {
    struct qmev_capture *c;
    int epfd, old_fd, client_fd, cs[2], n, i, seen_client = 0;
    struct epoll_event ev, out[8];

    g_sv[0] = -1;
    g_sv[1] = -1;
    epfd = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epfd >= 0, "epoll_create1");

    c = mk();
    CHECK(qmev_capture_observe_connected(c, "111", 1234, "10"), "worker starts");
    old_fd = g_sv[0];

    qmev_capture_epoll_sync(c, epfd);
    CHECK(c->reg_fd >= 0, "the live worker endpoint is registered");
    CHECK(c->reg_fd != old_fd, "registration uses a private dup, not the module fd");

    /* the worker endpoint dies; the module closes its own fd */
    close(g_sv[1]);
    g_sv[1] = -1;
    qmev_capture_tick(c);
    CHECK(qmev_capture_worker_fd(c) == -1, "dead worker released");

    /* a fresh client reuses the freed fd number */
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, cs) != 0) {
        abort();
    }
    client_fd = cs[0];
    CHECK(client_fd == old_fd, "precondition: the freed worker fd number is reused");
    ev.events = EPOLLIN;
    ev.data.ptr = &epoll_client_token;
    CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev) == 0, "client added to epoll");

    /* the next sync must unregister only its own dup, never the client */
    qmev_capture_epoll_sync(c, epfd);
    CHECK(c->reg_fd == -1, "the dead worker's registration is dropped");

    /* make the client readable so a surviving registration must fire */
    {
        char b = 'x';
        if (write(cs[1], &b, 1) != 1) {
            abort();
        }
    }
    n = epoll_wait(epfd, out, 8, 200);
    for (i = 0; i < n; i++) {
        if (out[i].data.ptr == &epoll_client_token) {
            seen_client = 1;
        }
    }
    CHECK(n >= 1 && seen_client,
          "the reused client fd must survive: no stale-number DEL of a foreign fd");

    close(cs[0]);
    close(cs[1]);
    close(epfd);
    fini(c);
}

/*
 * R3: the private worker socketpair must be CLOEXEC so an unrelated fork+exec
 * (the `qm cleanup` helper) can never inherit and keep alive the IPC endpoint.
 */
static void test_worker_pair_is_cloexec(void) {
    int sv[2];
    int f0, f1;

    CHECK(qmev_make_worker_pair(sv) == 0, "the private worker pair is created");
    f0 = fcntl(sv[0], F_GETFD);
    f1 = fcntl(sv[1], F_GETFD);
    CHECK(f0 >= 0 && (f0 & FD_CLOEXEC), "parent end is CLOEXEC");
    CHECK(f1 >= 0 && (f1 & FD_CLOEXEC), "child end is CLOEXEC");
    close(sv[0]);
    close(sv[1]);
}

/*
 * R1a: with no new observation and no EPOLLOUT, a tick must still drain an
 * outbound backlog (the old flush-on-successful-enqueue-only path never could).
 */
static void test_tick_drains_backlog_without_new_observations(void) {
    struct qmev_capture *c;
    char buf[8192];
    ssize_t n;
    int i, guard;

    fake_sndbuf = 2048;
    c = mk();
    fake_sndbuf = 2048; /* mk() resets the seams; re-assert before the spawn */
    for (i = 0; i < 400; i++) {
        qmev_capture_observe_connected(c, "111", 1234, "10");
    }
    CHECK(c->qcount > 0, "a backlog exists");

    for (guard = 0; guard < 10000 && c->qcount > 0; guard++) {
        while ((n = recv(g_sv[1], buf, sizeof(buf) - 1, MSG_DONTWAIT)) > 0) {
            (void)n;
        }
        qmev_capture_tick(c);
    }
    CHECK(c->qcount == 0,
          "tick alone must drain the backlog with no new observation and no EPOLLOUT");
    fini(c);
}

/*
 * R1b: replaying a large set of known identities into the bounded queue must
 * not permanently drop the overflow; the replay cursor resumes on later ticks.
 */
static void test_replay_of_many_vms_loses_none(void) {
    static char seen[2100];
    struct qmev_capture *c;
    struct qmev_capture_stats st = {0};
    char buf[8192];
    ssize_t n;
    int i, guard, distinct = 0;

    memset(seen, 0, sizeof(seen));
    c = mk();
    spawn_result = -1; /* worker unavailable while the 2000 VMs register */
    for (i = 1; i <= 2000; i++) {
        char vmid[16];
        snprintf(vmid, sizeof(vmid), "%d", i);
        qmev_capture_observe_connected(c, vmid, 1000 + i, "1000");
    }
    CHECK(qmev_capture_generation(c, "2000") == 2000, "all identities registered");

    spawn_result = 0;
    fake_sndbuf = 2048; /* force a full queue during the replay */
    fake_now += 120000; /* past the bounded backoff */

    for (guard = 0; guard < 100000 && distinct < 2000; guard++) {
        qmev_capture_tick(c);
        while ((n = recv(g_sv[1], buf, sizeof(buf) - 1, MSG_DONTWAIT)) > 0) {
            int v = -1;
            buf[n] = '\0';
            if (sscanf(buf, "{\"op\":\"observe\",\"kind\":\"connected\",\"vmid\":%d", &v) == 1 &&
                v >= 1 && v <= 2000 && !seen[v]) {
                seen[v] = 1;
                distinct++;
            }
        }
    }
    CHECK(distinct == 2000, "every known VM identity survives the replay (no permanent miss)");
    qmev_capture_get_stats(c, &st);
    CHECK(st.observations_sent >= 2000, "the replay actually enqueued the whole set");
    fini(c);
}

/*
 * R2: without an identity-stable pidfd handle the worker must never be killed
 * through a raw (reusable) PID, and must never be duplicated.
 */
static void test_unsupervised_worker_is_not_respawned(void) {
    struct qmev_capture *c;

    fake_pidfd_val = -1; /* pidfd_open() unavailable for the worker process */
    c = mk();
    fake_pidfd_val = -1;
    CHECK(qmev_capture_observe_connected(c, "111", 1234, "10"), "the channel still works");
    CHECK(qmev_capture_worker_pidfd(c) == -1, "no identity-stable handle");

    close(g_sv[1]);
    g_sv[1] = -1;
    qmev_capture_tick(c); /* loss detected, CANNOT be signalled by identity */

    CHECK(signal_calls == 0, "no bare (reusable) PID is ever killed");
    CHECK(qmev_capture_worker_fd(c) == -1, "the dead channel is closed");

    /* a duplicate worker we cannot identify or terminate must not be spawned */
    fake_now += 120000;
    qmev_capture_observe_connected(c, "111", 1234, "10");
    qmev_capture_tick(c);
    CHECK(spawn_calls == 1, "an unsupervised worker is never duplicated (fail-closed)");
    fini(c);
}

/* Old kernels without pidfd_open() must not run an unsupervised worker at all. */
static void test_pidfd_unsupported_disables_worker_fail_closed(void) {
    struct qmev_capture *c;

    probe_supported = 0;
    c = mk();
    probe_supported = 0;
    CHECK(!qmev_capture_observe_connected(c, "111", 1234, "10"),
          "no pidfd support => the worker is not started (fail-closed)");
    CHECK(spawn_calls == 0, "no unsupervised worker is ever spawned");
    CHECK(qmev_capture_worker_fd(c) == -1 && qmev_capture_worker_pidfd(c) == -1,
          "no worker channel is left open");

    qmev_capture_observe_connected(c, "222", 5678, "20");
    CHECK(spawn_calls == 0, "a disabled worker is never retried into a duplicate");
    CHECK(count_seam_event("CAPTURE_WORKER_UNAVAILABLE") == 1,
          "the fail-closed disable is reported once, not silently");
    CHECK(signal_calls == 0, "nothing is ever killed through a raw PID");
    fini(c);
}

/*
 * Provenance pairing: a QGA source may only report heartbeat results and a
 * capture source only screenshots, so a worker cannot mislabel its origin.
 */
static void test_source_event_pairing_is_enforced(void) {
    struct qmev_capture *c = mk();
    struct qmev_capture_stats st = {0};

    qmev_capture_observe_connected(c, "111", 1234, "10");
    log_count = 0;
    worker_send(
        "{\"op\":\"log\",\"vmid\":111,\"pid\":1234,\"starttime\":\"10\",\"generation\":1,"
        "\"level\":\"info\",\"source\":\"qga\",\"event\":\"SCREENSHOT_SAVED\"}"
    );
    worker_send(
        "{\"op\":\"log\",\"vmid\":111,\"pid\":1234,\"starttime\":\"10\",\"generation\":1,"
        "\"level\":\"info\",\"source\":\"capture\",\"event\":\"HEARTBEAT_READY\"}"
    );
    qmev_capture_handle_readable(c);
    CHECK(log_count == 0, "a mismatched source/event pair must be rejected");
    qmev_capture_get_stats(c, &st);
    CHECK(st.results_invalid == 2, "each mismatched pair is counted invalid");

    worker_send(
        "{\"op\":\"log\",\"vmid\":111,\"pid\":1234,\"starttime\":\"10\",\"generation\":1,"
        "\"level\":\"info\",\"source\":\"qga\",\"event\":\"HEARTBEAT_READY\"}"
    );
    worker_send(
        "{\"op\":\"log\",\"vmid\":111,\"pid\":1234,\"starttime\":\"10\",\"generation\":1,"
        "\"level\":\"warning\",\"source\":\"capture\",\"event\":\"SCREENSHOT_FAILED\"}"
    );
    qmev_capture_handle_readable(c);
    CHECK(log_count == 2, "the correctly paired results are accepted");
    fini(c);
}

/*
 * Fairness: a worker that streams messages must not be able to monopolise the
 * daemon loop. One readable callback processes a bounded number of packets.
 */
static void test_recv_loop_is_bounded(void) {
    struct qmev_capture *c = mk();
    struct qmev_capture_stats st = {0};
    const char *pkt =
        "{\"op\":\"log\",\"vmid\":111,\"pid\":1234,\"starttime\":\"10\",\"generation\":1,"
        "\"level\":\"info\",\"source\":\"qga\",\"event\":\"HEARTBEAT_READY\"}";
    int i;

    qmev_capture_observe_connected(c, "111", 1234, "10");
    log_count = 0;
    for (i = 0; i < QMEV_CAPTURE_READ_BUDGET + 50; i++) {
        worker_send(pkt);
    }
    qmev_capture_handle_readable(c);
    qmev_capture_get_stats(c, &st);
    CHECK(st.results_accepted >= 1, "some packets are processed");
    CHECK(st.results_accepted <= QMEV_CAPTURE_READ_BUDGET,
          "one callback processes at most the fairness budget");

    qmev_capture_handle_readable(c); /* the remainder, without starving the loop */
    qmev_capture_get_stats(c, &st);
    CHECK(st.results_accepted == QMEV_CAPTURE_READ_BUDGET + 50,
          "the remainder is processed on the next callback");
    fini(c);
}

static void test_disconnect_overflow_invalidates_worker_state(void) {
    struct qmev_capture *c = mk();
    struct json_object *event = mj("{\"event\":\"STOP\"}");
    char buf[8192];
    int i;

    fake_sndbuf = 2048;
    qmev_capture_observe_connected(c, "111", 1234, "10");
    for (i = 0; i < QMEV_CAPTURE_QUEUE_MAX + 30; i++) {
        qmev_capture_observe_event(c, "111", "STOP", event);
    }
    CHECK(c->qcount == QMEV_CAPTURE_QUEUE_MAX, "fixture fills the outbound queue");
    qmev_capture_observe_disconnected(c, "111");
    CHECK(qmev_capture_generation(c, "111") == 0, "disconnected identity is forgotten");
    CHECK(qmev_capture_worker_fd(c) == -1,
          "a lost disconnect must invalidate the old worker, not leave a ghost VM");
    fake_now += 120000;
    qmev_capture_tick(c);
    CHECK(recv_pkt(buf, sizeof(buf)) <= 0, "removed VM is not replayed into the new worker");
    json_object_put(event);
    fini(c);
}

static void test_repeated_worker_exits_increase_backoff(void) {
    struct qmev_capture *c = mk();
    uint64_t first;
    qmev_capture_observe_connected(c, "111", 1234, "10");
    close(g_sv[1]);
    g_sv[1] = -1;
    qmev_capture_tick(c);
    first = c->backoff_ms;
    fake_now = c->next_retry_ms;
    qmev_capture_tick(c);
    CHECK(spawn_calls == 2, "worker restarted after its deadline");
    close(g_sv[1]);
    g_sv[1] = -1;
    qmev_capture_tick(c);
    CHECK(c->backoff_ms > first, "a crash loop must back off across successful fork/exec");
    fini(c);
}

int main(void) {
    struct {
        const char *name;
        void (*fn)(void);
    } tests[] = {
        {"connected_packet_shape", test_connected_packet_shape},
        {"new_connection_advances_generation", test_new_connection_advances_generation},
        {"untrusted_connected_identity_is_rejected", test_untrusted_connected_identity_is_rejected},
        {"valid_worker_result_is_logged", test_valid_worker_result_is_logged},
        {"stale_generation_result_is_dropped", test_stale_generation_result_is_dropped},
        {"mismatched_identity_result_is_dropped", test_mismatched_identity_result_is_dropped},
        {"unsafe_source_event_or_level_is_rejected", test_unsafe_source_event_or_level_is_rejected},
        {"worker_cannot_command_the_vm", test_worker_cannot_command_the_vm},
        {"malformed_worker_packet_is_rejected", test_malformed_worker_packet_is_rejected},
        {"lifecycle_event_is_forwarded", test_lifecycle_event_is_forwarded},
        {"reset_advances_generation", test_reset_advances_generation},
        {"non_whitelisted_event_is_not_forwarded", test_non_whitelisted_event_is_not_forwarded},
        {"event_for_unassociated_client_is_dropped", test_event_for_unassociated_client_is_dropped},
        {"panic_events_are_forwarded_with_full_object",
         test_panic_events_are_forwarded_with_full_object},
        {"migration_event_is_forwarded", test_migration_event_is_forwarded},
        {"disconnected_is_forwarded_then_identity_forgotten",
         test_disconnected_is_forwarded_then_identity_forgotten},
        {"backup_observation_maps_to_qemu_identity", test_backup_observation_maps_to_qemu_identity},
        {"backup_for_unknown_vmid_is_dropped", test_backup_for_unknown_vmid_is_dropped},
        {"queue_is_bounded_and_drops_reported", test_queue_is_bounded_and_drops_reported},
        {"oversized_observation_packet_is_refused", test_oversized_observation_packet_is_refused},
        {"oversized_worker_packet_is_rejected", test_oversized_worker_packet_is_rejected},
        {"worker_restart_replays_known_vms_with_latest_generation",
         test_worker_restart_replays_known_vms_with_latest_generation},
        {"spawn_failure_backs_off_and_reports_once", test_spawn_failure_backs_off_and_reports_once},
        {"worker_liveness_and_bounded_timeout", test_worker_liveness_and_bounded_timeout},
        {"worker_path_is_fixed", test_worker_path_is_fixed},
        {"arm_child_lifetime", test_arm_child_lifetime},
        {"close_fds_from_closes_everything_high", test_close_fds_from_closes_everything_high},
        {"read_starttime_matches_proc", test_read_starttime_matches_proc},
        {"read_starttime_missing_pid", test_read_starttime_missing_pid},
        {"worker_termination_uses_pidfd_identity", test_worker_termination_uses_pidfd_identity},
        {"epoll_sync_never_deletes_a_reused_fd", test_epoll_sync_never_deletes_a_reused_fd},
        {"worker_pair_is_cloexec", test_worker_pair_is_cloexec},
        {"tick_drains_backlog_without_new_observations",
         test_tick_drains_backlog_without_new_observations},
        {"replay_of_many_vms_loses_none", test_replay_of_many_vms_loses_none},
        {"unsupervised_worker_is_not_respawned", test_unsupervised_worker_is_not_respawned},
        {"pidfd_unsupported_disables_worker_fail_closed",
         test_pidfd_unsupported_disables_worker_fail_closed},
        {"source_event_pairing_is_enforced", test_source_event_pairing_is_enforced},
        {"recv_loop_is_bounded", test_recv_loop_is_bounded},
        {"disconnect_overflow_invalidates_worker_state",
         test_disconnect_overflow_invalidates_worker_state},
        {"repeated_worker_exits_increase_backoff", test_repeated_worker_exits_increase_backoff},
    };
    size_t i;
    int pfd[2];
    if (pipe(pfd) != 0) {
        abort();
    }
    g_pidfd_src = pfd[0];
    g_pidfd_wr = pfd[1];
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        tests_run++;
        fprintf(stderr, "RUN %s\n", tests[i].name);
        tests[i].fn();
    }
    fprintf(stderr, "qmeventd capture tests: %d run, %d failed\n", tests_run, tests_failed);
    return tests_failed ? 1 : 0;
}
