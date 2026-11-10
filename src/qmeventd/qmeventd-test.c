// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    Unit/protocol regression tests for qmeventd key-event journal logging.

    The production source is compiled into this translation unit with its
    main() renamed, so the internal handlers can be exercised directly against
    isolated sockets. All process side effects (kill/fork/execvp/_exit) are
    replaced by linker --wrap doubles; no real VM, socket or /usr/sbin/qm is
    ever touched.
*/

#define _GNU_SOURCE
#define main qmeventd_program_main
#include "qmeventd.c"
#undef main

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* test doubles                                                       */
/* ------------------------------------------------------------------ */

static int wrap_kill_calls = 0;
static pid_t wrap_kill_last_pid = 0;
static int wrap_kill_last_sig = 0;
static int wrap_kill_ret = 0;
static int wrap_kill_errno = 0;

int __wrap_kill(pid_t pid, int sig) {
    wrap_kill_calls++;
    wrap_kill_last_pid = pid;
    wrap_kill_last_sig = sig;
    if (wrap_kill_ret < 0 && wrap_kill_errno) {
        errno = wrap_kill_errno;
    }
    return wrap_kill_ret;
}

static int wrap_fork_calls = 0;
static pid_t wrap_fork_ret = 4242; /* > 0 => parent branch */

pid_t __wrap_fork(void) {
    wrap_fork_calls++;
    return wrap_fork_ret;
}

static int wrap_execvp_calls = 0;
static char wrap_execvp_file[64];
static char wrap_execvp_args[8][64];

/*
 * The cleanup child branch ends in execvp()/_exit(). glibc declares _exit
 * noreturn, so a wrapper that simply "returns" is undefined behaviour (the
 * compiler may exploit the missing return path). Instead the doubles jump
 * back into the test, which is what would really happen to control flow.
 */
static jmp_buf exec_jmp;
static int exec_landing = 0;
static int wrap_exit_seen = 0;
static int wrap_exit_status = -1;

int __wrap_execvp(const char *file, char *const argv[]) {
    size_t i;
    wrap_execvp_calls++;
    snprintf(wrap_execvp_file, sizeof(wrap_execvp_file), "%s", file ? file : "(null)");
    for (i = 0; i < 7 && argv && argv[i]; i++) {
        snprintf(wrap_execvp_args[i], sizeof(wrap_execvp_args[i]), "%s", argv[i]);
    }
    for (; i < 8; i++) {
        wrap_execvp_args[i][0] = '\0';
    }
    return -1; /* exec failed: the child logs and then calls _exit() */
}

void __wrap__exit(int status) {
    wrap_exit_seen = 1;
    wrap_exit_status = status;
    longjmp(exec_jmp, 2); /* never returns, as a real _exit would not */
}

/* fake /proc/<pid>/cmdline for get_vmid_from_pid() */
static const char *fake_cmdline = NULL;
static size_t fake_cmdline_len = 0;

/* fake /proc/<pid>/stat for qmev_read_starttime() */
static char fake_stat_buf[256];
static const char *fake_stat = NULL;

extern FILE *__real_fopen(const char *path, const char *mode);

FILE *__wrap_fopen(const char *path, const char *mode) {
    if (path && strstr(path, "/proc/") && strstr(path, "/stat")) {
        if (!fake_stat) {
            return NULL;
        }
        return fmemopen((void *)fake_stat, strlen(fake_stat), "r");
    }
    if (path && strstr(path, "/proc/") && strstr(path, "cmdline")) {
        if (!fake_cmdline) {
            return NULL;
        }
        return fmemopen((void *)fake_cmdline, fake_cmdline_len, "r");
    }
    return __real_fopen(path, mode);
}

/* build a plausible stat line: 20 tokens after ')' with field 22 = starttime */
void set_fake_stat(unsigned long pid, const char *starttime) {
    int n = snprintf(fake_stat_buf, sizeof(fake_stat_buf), "%lu (qemu-system-x86_64) R ", pid);
    int i;
    for (i = 0; i < 18; i++) {
        n += snprintf(fake_stat_buf + n, sizeof(fake_stat_buf) - (size_t)n, "0 ");
    }
    snprintf(fake_stat_buf + n, sizeof(fake_stat_buf) - (size_t)n, "%s", starttime);
    fake_stat = fake_stat_buf;
}

void set_fake_cmdline_vmid(unsigned long vmid) {
    static char buf[128];
    int n = snprintf(
        buf, sizeof(buf), "qemu-system-x86_64%c-pidfile%c/run/qemu-server/%lu.pid%c", '\0', '\0',
        vmid, '\0'
    );
    fake_cmdline = buf;
    fake_cmdline_len = (size_t)n;
}

/* ------------------------------------------------------------------ */
/* harness                                                            */
/* ------------------------------------------------------------------ */

/* ---- capture bridge (private supervised worker) ------------------ */
static int cap_sv[2] = {-1, -1};
static int cap_spawn_calls = 0;

static int cap_spawn(void *ud, int *parent_fd_out, pid_t *pid_out) {
    (void)ud;
    cap_spawn_calls++;
    if (cap_sv[1] >= 0) {
        close(cap_sv[1]);
    }
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, cap_sv) != 0) {
        abort();
    }
    *parent_fd_out = cap_sv[0];
    *pid_out = 4242;
    return 0;
}

static void capture_install(void) {
    struct qmev_capture_seams s;
    if (capture_mod) {
        qmev_capture_free(capture_mod);
        capture_mod = NULL;
    }
    if (cap_sv[0] >= 0) {
        close(cap_sv[0]);
        cap_sv[0] = -1;
    }
    if (cap_sv[1] >= 0) {
        close(cap_sv[1]);
        cap_sv[1] = -1;
    }
    cap_spawn_calls = 0;
    memset(&s, 0, sizeof(s));
    s.spawn = cap_spawn;
    capture_mod = qmev_capture_new(&s);
}

static void capture_uninstall(void) {
    if (capture_mod) {
        qmev_capture_free(capture_mod);
        capture_mod = NULL;
    }
    if (cap_sv[0] >= 0) {
        close(cap_sv[0]);
        cap_sv[0] = -1;
    }
    if (cap_sv[1] >= 0) {
        close(cap_sv[1]);
        cap_sv[1] = -1;
    }
    cap_spawn_calls = 0;
}

static size_t cap_recv(char *out, size_t cap) {
    ssize_t n = recv(cap_sv[1], out, cap - 1, MSG_DONTWAIT);
    out[n > 0 ? (size_t)n : 0] = '\0';
    return n > 0 ? (size_t)n : 0;
}

static const char *cap_jstr(struct json_object *o, const char *k) {
    struct json_object *v;
    return (o && json_object_object_get_ex(o, k, &v)) ? json_object_get_string(v) : NULL;
}

static long long cap_jint(struct json_object *o, const char *k) {
    struct json_object *v;
    return (o && json_object_object_get_ex(o, k, &v)) ? (long long)json_object_get_int64(v) : -999;
}

static int log_rfd = -1;
static int log_wfd = -1;
static int tests_run = 0;
static int tests_failed = 0;

static size_t drain_fd(int fd, char *out, size_t cap); /* defined in group 3 */

static void logtest_setup(void) {
    int sv[2];
    /* any leftover state of the previous test is discarded */
    if (capture_mod) {
        qmev_capture_free(capture_mod);
        capture_mod = NULL;
    }
    if (cap_sv[0] >= 0) {
        close(cap_sv[0]);
        cap_sv[0] = -1;
    }
    if (cap_sv[1] >= 0) {
        close(cap_sv[1]);
        cap_sv[1] = -1;
    }
    cap_spawn_calls = 0;
    fake_stat = NULL;
    if (log_rfd >= 0) {
        close(log_rfd);
        close(log_wfd);
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }
    log_wfd = sv[0];
    log_rfd = sv[1];
    fcntl(log_rfd, F_SETFL, O_NONBLOCK);
    qmeventd_log_init(log_wfd);
    qmeventd_log_reset_stats();
    fake_cmdline = NULL;
    fake_cmdline_len = 0;
    wrap_kill_calls = 0;
    wrap_kill_ret = 0;
    wrap_fork_calls = 0;
    wrap_fork_ret = 4242;
    wrap_execvp_calls = 0;
    exec_landing = 0;
    wrap_exit_seen = 0;
    wrap_exit_status = -1;
}

static size_t drain_log(char *out, size_t cap) {
    size_t total = 0;
    for (;;) {
        ssize_t n;
        if (total + 1 >= cap) {
            break;
        }
        n = read(log_rfd, out + total, cap - total - 1);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        break;
    }
    out[total] = '\0';
    return total;
}

static int count_lines(const char *s) {
    int n = 0;
    for (const char *p = s; *p; p++) {
        if (*p == '\n') {
            n++;
        }
    }
    return n;
}

/*
 * Some failure paths (get_vmid_from_pid) deliberately fprintf(stderr). The
 * outer test would otherwise emit that expected noise; silence stderr only
 * around the call, then restore it so real CHECK failures stay visible.
 */
static int stderr_saved = -1;
static void silence_stderr(void) {
    int devnull;
    if (stderr_saved >= 0) {
        return;
    }
    fflush(stderr);
    stderr_saved = dup(STDERR_FILENO);
    devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        (void)dup2(devnull, STDERR_FILENO);
        close(devnull);
    }
}
static void restore_stderr(void) {
    if (stderr_saved < 0) {
        return;
    }
    fflush(stderr);
    (void)dup2(stderr_saved, STDERR_FILENO);
    close(stderr_saved);
    stderr_saved = -1;
}

static struct Client *mk_client(ClientType type, const char *vmid, pid_t pid, int fd) {
    struct Client *c = calloc(1, sizeof(struct Client));
    if (!c) {
        abort();
    }
    c->type = type;
    c->state = STATE_IDLE;
    c->fd = fd;
    c->pid = pid;
    c->pidfd = -1;
    if (vmid) {
        snprintf(c->qemu.vmid, sizeof(c->qemu.vmid), "%s", vmid);
    }
    return c;
}

/* give a client a live socketpair so QMP replies/queries can be sent */
static int g_epoll_fd = -1;

static void mk_client_sockpair(struct Client *c, int sv[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }
    c->fd = sv[0];
    /* keep the fixture honest: cleanup_client() removes the fd from the epoll
     * set, so the client must have been added, exactly like in production */
    if (g_epoll_fd >= 0) {
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.ptr = c;
        (void)epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, c->fd, &ev);
    }
}

static void base_globals_init(void) {
    if (vm_clients) {
        g_hash_table_destroy(vm_clients);
    }
    vm_clients = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
    if (g_epoll_fd < 0) {
        g_epoll_fd = epoll_create1(0);
    }
    epoll_fd = g_epoll_fd;
    forced_cleanups = NULL;
    needs_cleanup = 0;
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
/* group 1: QMP event whitelist + format                              */
/* ------------------------------------------------------------------ */

static void test_qmp_stop_event_is_logged(void) {
    struct Client *c;
    struct json_object *obj;
    char out[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, -1);
    obj = json_tokener_parse(
        "{\"event\":\"STOP\",\"timestamp\":{\"seconds\":1,\"microseconds\":2}}"
    );
    handle_qmp_event(c, obj);
    json_object_put(obj);

    drain_log(out, sizeof(out));
    CHECK(count_lines(out) == 1, "STOP must produce exactly one log line");
    CHECK(strncmp(out, "<6>", 3) == 0, "INFO must carry the pure severity prefix <6>");
    CHECK(strstr(out, "vmid=100 ") != NULL, "line must carry the vmid");
    CHECK(strstr(out, "level=info source=qmp event=STOP ") != NULL, "level/source/event fields");
    CHECK(strstr(out, "payload={\"event\":\"STOP\"") != NULL, "payload must keep the full object");
    CHECK(strstr(out, "\"timestamp\"") != NULL, "payload must keep the original timestamp");
    free(c);
}

/*
 * systemd's SyslogLevelPrefix parser for standard streams only understands a
 * bare severity (<0..7>). A facility-encoded value such as <14> (<12>/<11>)
 * is kept verbatim in MESSAGE and the journal PRIORITY stays at the default,
 * so the level mapping silently fails. This test pins the pure-severity form
 * and requires the prefix to be consumed (it must not remain in the text).
 */
static void test_priority_prefix_is_pure_severity(void) {
    struct {
        QLogLevel level;
        const char *prefix;
    } cases[] = {
        {QLOG_INFO, "<6>"},
        {QLOG_WARNING, "<4>"},
        {QLOG_ERROR, "<3>"},
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char out[8192];
        logtest_setup();
        base_globals_init();
        qmeventd_log_event("100", 101, 101, cases[i].level, "qmeventd", "PRIO_PROBE", NULL);
        drain_log(out, sizeof(out));
        CHECK(strncmp(out, cases[i].prefix, strlen(cases[i].prefix)) == 0,
              "prefix must be the bare severity");
        CHECK(strncmp(out + strlen(cases[i].prefix), "vmid=", 5) == 0,
              "MESSAGE must start with the record right after the prefix");
        CHECK(strstr(out, "facility") == NULL, "no facility text in the record");
    }
}

static void test_unknown_event_is_not_logged(void) {
    struct Client *c;
    struct json_object *obj;
    char out[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, -1);
    obj = json_tokener_parse("{\"event\":\"BALLOON_CHANGE\",\"data\":{\"actual\":1}}");
    handle_qmp_event(c, obj);
    json_object_put(obj);

    drain_log(out, sizeof(out));
    CHECK(out[0] == '\0', "non-whitelisted event must not be logged by default");
    free(c);
}

static void test_error_events_are_logged_at_error_level(void) {
    const char *events[] = {"GUEST_PANICKED", "BLOCK_IO_ERROR", "BLOCK_JOB_ERROR"};
    size_t i;
    for (i = 0; i < sizeof(events) / sizeof(events[0]); i++) {
        struct Client *c;
        struct json_object *obj;
        char in[256];
        char out[8192];

        logtest_setup();
        base_globals_init();
        c = mk_client(CLIENT_QEMU, "100", 1234, -1);
        snprintf(in, sizeof(in), "{\"event\":\"%s\",\"data\":{\"x\":1}}", events[i]);
        obj = json_tokener_parse(in);
        handle_qmp_event(c, obj);
        json_object_put(obj);

        drain_log(out, sizeof(out));
        CHECK(strncmp(out, "<3>", 3) == 0, "ERROR events must carry the pure severity prefix <3>");
        CHECK(strstr(out, "level=error source=qmp ") != NULL, "level=error expected");
        CHECK(strstr(out, events[i]) != NULL, "event name must be present");
        free(c);
    }
}

static void test_watchdog_is_logged_at_warning_level(void) {
    struct Client *c;
    struct json_object *obj;
    char out[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, -1);
    obj = json_tokener_parse(
        "{\"event\":\"WATCHDOG\",\"data\":{\"action\":\"reset\"}}"
    );
    handle_qmp_event(c, obj);
    json_object_put(obj);

    drain_log(out, sizeof(out));
    CHECK(strncmp(out, "<4>", 3) == 0, "WARNING must carry the pure severity prefix <4>");
    CHECK(strstr(out, "level=warning source=qmp event=WATCHDOG ") != NULL, "warning watchdog");
    CHECK(strstr(out, "\"action\":\"reset\"") != NULL, "watchdog action must be preserved");
    free(c);
}

/*
 * GUEST_CRASHLOADED is the Windows pvpanic crash-dump path notification. It is
 * a distinct fact from GUEST_PANICKED (it does NOT mean the dump finished) and
 * must not be filtered out by the default whitelist, otherwise the whole
 * crash-dump path is invisible in the journal.
 */
static void test_guest_crashloaded_is_logged_at_error_level(void) {
    struct Client *c;
    struct json_object *obj;
    char out[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, -1);
    obj = json_tokener_parse(
        "{\"event\":\"GUEST_CRASHLOADED\",\"data\":{\"reason\":\"guest-crash-loaded\"}}"
    );
    handle_qmp_event(c, obj);
    json_object_put(obj);

    drain_log(out, sizeof(out));
    CHECK(count_lines(out) == 1, "GUEST_CRASHLOADED must produce exactly one log line");
    CHECK(strncmp(out, "<3>", 3) == 0, "CRASHLOADED must carry the pure severity prefix <3>");
    CHECK(strstr(out, "level=error source=qmp event=GUEST_CRASHLOADED ") != NULL,
          "level/source/event fields");
    CHECK(strstr(out, "\"reason\":\"guest-crash-loaded\"") != NULL,
          "the full raw event must be preserved");
    free(c);
}

static void test_logged_before_terminating_early_return(void) {
    struct Client *c;
    struct json_object *obj;
    char out[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, -1);
    c->state = STATE_TERMINATING;
    obj = json_tokener_parse("{\"event\":\"SHUTDOWN\",\"data\":{\"guest\":true}}");
    handle_qmp_event(c, obj);
    json_object_put(obj);

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "event=SHUTDOWN") != NULL, "event after termination must still be recorded");
    /* original business behaviour preserved: graceful not set once terminating */
    CHECK(c->qemu.graceful == 0, "terminating state must keep ignoring the SHUTDOWN side effects");
    free(c);
}

static void test_shutdown_keeps_guest_and_reason(void) {
    struct Client *c;
    struct json_object *obj;
    char out[8192];
    int sv[2];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, 0);
    mk_client_sockpair(c, sv);
    obj = json_tokener_parse(
        "{\"event\":\"SHUTDOWN\",\"data\":{\"guest\":false,\"reason\":\"host-qmp-quit\"}}"
    );
    handle_qmp_event(c, obj);
    json_object_put(obj);

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "\"guest\":false") != NULL, "guest flag must be preserved verbatim");
    CHECK(strstr(out, "\"reason\":\"host-qmp-quit\"") != NULL, "reason must be preserved verbatim");
    /* business side effect still works */
    CHECK(c->qemu.graceful == 1, "SHUTDOWN must still mark graceful");
    CHECK(c->qemu.guest == 0, "SHUTDOWN must still record guest=false");
    close(sv[0]);
    close(sv[1]);
    free(c);
}

static void test_payload_cannot_inject_newlines(void) {
    struct Client *c;
    struct json_object *obj;
    char out[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, -1);
    obj = json_tokener_parse(
        "{\"event\":\"BLOCK_IO_ERROR\",\"data\":{\"reason\":\"a\\nb\\r\\t\\\"c\\\"\"}}"
    );
    handle_qmp_event(c, obj);
    json_object_put(obj);

    drain_log(out, sizeof(out));
    CHECK(count_lines(out) == 1, "control characters must not break the single-line format");
    CHECK(strstr(out, "\\n") != NULL, "newline must be escaped inside the JSON payload");
    free(c);
}

static void test_vmid_not_confused_between_clients(void) {
    struct Client *c100;
    struct Client *c1000;
    struct json_object *o1;
    struct json_object *o2;
    char out[8192];

    logtest_setup();
    base_globals_init();
    c100 = mk_client(CLIENT_QEMU, "100", 11, -1);
    c1000 = mk_client(CLIENT_QEMU, "1000", 22, -1);

    o1 = json_tokener_parse("{\"event\":\"STOP\"}");
    o2 = json_tokener_parse("{\"event\":\"RESUME\"}");
    handle_qmp_event(c100, o1);
    handle_qmp_event(c1000, o2);
    json_object_put(o1);
    json_object_put(o2);

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "vmid=100 qemu_pid=11 ") != NULL, "VM 100 line must be self-consistent");
    CHECK(strstr(out, "vmid=1000 qemu_pid=22 ") != NULL, "VM 1000 line must be self-consistent");
    free(c100);
    free(c1000);
}

/* ------------------------------------------------------------------ */
/* group 2: qmeventd flow events, backup guard, termination           */
/* ------------------------------------------------------------------ */

static struct json_object *J(const char *s) {
    struct json_object *o = json_tokener_parse(s);
    if (!o) {
        fprintf(stderr, "bad test json: %s\n", s);
        abort();
    }
    return o;
}

static void test_qmp_connected_on_handshake(void) {
    struct Client *c;
    int sv[2];
    char out[8192];

    logtest_setup();
    base_globals_init();
    set_fake_cmdline_vmid(100);
    c = mk_client(CLIENT_QEMU, NULL, 1234, 0);
    mk_client_sockpair(c, sv);
    c->state = STATE_HANDSHAKE;

    handle_qmp_handshake(c);

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "level=info source=qmeventd event=QMP_CONNECTED ") != NULL, "handshake log");
    CHECK(strstr(out, "vmid=100 qemu_pid=1234 peer_pid=1234 ") != NULL, "vmid/pid fields");
    CHECK(c->type == CLIENT_QEMU, "handshake must still register the client as QEMU");
    CHECK(g_hash_table_lookup(vm_clients, "100") == c, "client must be reachable by vmid");
    close(sv[0]);
    close(sv[1]);
    free(c);
}

static void test_qmp_handshake_failure_logged_as_protocol_error(void) {
    struct Client *c;
    int sv[2];
    char out[8192];

    logtest_setup();
    base_globals_init();
    fake_cmdline = NULL; /* get_vmid_from_pid() cannot resolve a VMID */
    c = mk_client(CLIENT_NONE, NULL, 1234, 0);
    mk_client_sockpair(c, sv);
    c->state = STATE_HANDSHAKE;

    silence_stderr(); /* the vmid resolution failure prints to stderr */
    handle_qmp_handshake(c); /* frees the client on failure */
    restore_stderr();

    drain_log(out, sizeof(out));
    CHECK(
        strstr(out, "level=warning source=qmeventd event=PROTOCOL_ERROR ") != NULL,
        "protocol error"
    );
    CHECK(strstr(out, "vmid=- qemu_pid=- peer_pid=1234 ") != NULL,
          "an unidentified connection must claim neither a VMID nor a QEMU pid");
    close(sv[1]);
}

static void test_qmp_disconnected_and_cleanup_requested(void) {
    struct Client *c;
    int sv[2];
    char out[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, 0);
    mk_client_sockpair(c, sv);
    g_hash_table_insert(vm_clients, strdup("100"), c);

    cleanup_client(c); /* frees the client */

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "event=QMP_DISCONNECTED ") != NULL, "disconnect must be recorded");
    CHECK(strstr(out, "event=CLEANUP_REQUESTED ") != NULL, "cleanup request must be recorded");
    CHECK(wrap_fork_calls == 1, "cleanup still forks once");
    CHECK(wrap_execvp_calls == 0, "parent branch must not exec");
    close(sv[1]);
}

static void test_backup_guard_enter_and_leave(void) {
    struct Client *q;
    struct Client *v;
    struct json_object *obj;
    int svq[2];
    int svv[2];
    char out[8192];

    logtest_setup();
    base_globals_init();
    q = mk_client(CLIENT_QEMU, "100", 1234, 0);
    mk_client_sockpair(q, svq);
    g_hash_table_insert(vm_clients, strdup("100"), q);

    v = mk_client(CLIENT_NONE, NULL, 5555, 0);
    mk_client_sockpair(v, svv);
    v->state = STATE_HANDSHAKE;
    obj = J("{\"vmid\":\"100\"}");
    handle_vzdump_handshake(v, obj);
    json_object_put(obj);

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "level=info source=vzdump event=BACKUP_GUARD_ENTER ") != NULL, "guard enter");
    CHECK(strstr(out, "vmid=100 qemu_pid=1234 peer_pid=5555 ") != NULL, "vzdump/pids separated");
    CHECK(v->type == CLIENT_VZDUMP, "vzdump client must be typed after a valid handshake");
    CHECK(q->qemu.backup == true, "guard must still protect the VM");

    cleanup_client(v); /* frees the vzdump client */

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "level=info source=vzdump event=BACKUP_GUARD_LEAVE ") != NULL, "guard leave");
    CHECK(q->qemu.backup == false, "guard release must still clear the flag");

    close(svq[1]);
    close(svv[1]);
    free(q);
}

static void test_vzdump_unregistered_vmid_is_protocol_error(void) {
    struct Client *v;
    struct json_object *obj;
    int svv[2];
    char out[8192];

    logtest_setup();
    base_globals_init();
    v = mk_client(CLIENT_NONE, NULL, 5555, 0);
    mk_client_sockpair(v, svv);
    v->state = STATE_HANDSHAKE;
    obj = J("{\"vmid\":\"999\"}");
    handle_vzdump_handshake(v, obj);
    json_object_put(obj);

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "level=warning source=vzdump event=PROTOCOL_ERROR ") != NULL, "unknown vmid");
    CHECK(strstr(out, "BACKUP_GUARD_ENTER") == NULL, "no guard must be claimed");
    CHECK(v->type == CLIENT_NONE, "unknown VM must not be typed as vzdump");
    close(svv[0]);
    close(svv[1]);
    free(v);
}

static void test_vm_status_changed_logged_once(void) {
    struct Client *c;
    struct json_object *running;
    struct json_object *paused;
    int sv[2];
    char out[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, 0);
    mk_client_sockpair(c, sv);
    running = J("{\"status\":\"running\"}");
    paused = J("{\"status\":\"paused\"}");

    c->state = STATE_EXPECT_STATUS_RESP;
    handle_qmp_return(c, running, false);
    drain_log(out, sizeof(out));
    CHECK(strstr(out, "event=VM_STATUS_CHANGED ") != NULL, "first status must be recorded");
    CHECK(strstr(out, "\"status\":\"running\"") != NULL, "status value preserved");

    c->state = STATE_EXPECT_STATUS_RESP;
    handle_qmp_return(c, running, false);
    drain_log(out, sizeof(out));
    CHECK(out[0] == '\0', "identical status must not be logged again");

    c->state = STATE_EXPECT_STATUS_RESP;
    handle_qmp_return(c, paused, false);
    drain_log(out, sizeof(out));
    CHECK(strstr(out, "\"status\":\"paused\"") != NULL, "a real change must be recorded");

    json_object_put(running);
    json_object_put(paused);
    close(sv[0]);
    close(sv[1]);
    free(c);
}

static void test_termination_deferred_logged_once(void) {
    struct Client *c;
    struct json_object *shutdown;
    int sv[2];
    char out[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, 0);
    mk_client_sockpair(c, sv);
    c->qemu.backup = true;
    shutdown = J("{\"status\":\"shutdown\"}");

    c->state = STATE_EXPECT_STATUS_RESP;
    handle_qmp_return(c, shutdown, false);
    drain_log(out, sizeof(out));
    CHECK(strstr(out, "event=TERMINATION_DEFERRED ") != NULL, "deferred termination recorded");

    c->state = STATE_EXPECT_STATUS_RESP;
    handle_qmp_return(c, shutdown, false);
    drain_log(out, sizeof(out));
    CHECK(out[0] == '\0', "deferred state must not be logged repeatedly");

    json_object_put(shutdown);
    close(sv[0]);
    close(sv[1]);
    free(c);
}

static void test_qmp_error_logged(void) {
    struct Client *c;
    struct json_object *err;
    int sv[2];
    char out[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, 0);
    mk_client_sockpair(c, sv);
    err = J("{\"class\":\"GenericError\",\"desc\":\"boom\"}");

    handle_qmp_return(c, err, true);

    drain_log(out, sizeof(out));
    CHECK(strncmp(out, "<3>", 3) == 0, "QMP error is ERROR level");
    CHECK(strstr(out, "level=error source=qmeventd event=QMP_ERROR ") != NULL, "qmp error event");
    CHECK(strstr(out, "boom") != NULL, "error description preserved");
    CHECK(c->state == STATE_IDLE, "control state must be unchanged");

    json_object_put(err);
    close(sv[0]);
    close(sv[1]);
    free(c);
}

static void test_quit_requested_and_sigterm_fallback(void) {
    struct Client *c;
    char out[8192];

    logtest_setup();
    base_globals_init();
    /* fd = -1 makes the QMP 'quit' write fail -> SIGTERM fallback */
    c = mk_client(CLIENT_QEMU, "100", getpid(), -1);
    wrap_kill_ret = 0;

    terminate_client(c);

    drain_log(out, sizeof(out));
    CHECK(
        strstr(out, "level=info source=qmeventd event=QMP_QUIT_REQUESTED ") != NULL, "quit attempt"
    );
    CHECK(
        strstr(out, "level=warning source=qmeventd event=SIGTERM_FALLBACK ") != NULL,
        "sigterm fallback"
    );
    CHECK(wrap_kill_calls == 1 && wrap_kill_last_sig == SIGTERM, "real SIGTERM still sent");
    CHECK(c->state == STATE_TERMINATING, "control state must be unchanged");
    CHECK(needs_cleanup == 1, "forced cleanup must still be armed");

    forced_cleanups = g_slist_remove(forced_cleanups, c);
    if (c->pidfd > 0) {
        close(c->pidfd);
    }
    free(c);
}

static void test_cleanup_requested_preserves_exec_arguments(void) {
    struct Client *c;
    int sv[2];
    int cap[2];
    int saved2;
    char out[8192];
    char cerr[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, 0);
    mk_client_sockpair(c, sv);
    c->qemu.graceful = 1;
    c->qemu.guest = 0;
    wrap_fork_ret = 0; /* take the child branch so exec is exercised */

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, cap) != 0) {
        abort();
    }
    saved2 = dup(STDERR_FILENO);
    (void)dup2(cap[0], STDERR_FILENO); /* the child reports on its own stream */

    exec_landing = setjmp(exec_jmp);
    if (exec_landing == 0) {
        cleanup_client(c); /* child branch: execvp/_exit double jumps back */
        CHECK(0, "cleanup child branch must not return normally");
    } else {
        /* jumped back out of the child branch; the client is not freed yet */
        free(c);
    }

    (void)dup2(saved2, STDERR_FILENO);
    close(saved2);

    drain_log(out, sizeof(out));
    drain_fd(cap[1], cerr, sizeof(cerr));
    CHECK(strstr(out, "event=CLEANUP_REQUESTED ") != NULL, "cleanup request recorded");
    CHECK(wrap_execvp_calls == 1, "cleanup must still exec");
    CHECK(strcmp(wrap_execvp_file, "/usr/sbin/qm") == 0, "cleanup target unchanged");
    CHECK(strcmp(wrap_execvp_args[1], "cleanup") == 0, "subcommand unchanged");
    CHECK(strcmp(wrap_execvp_args[2], "100") == 0, "vmid argument unchanged");
    CHECK(strcmp(wrap_execvp_args[3], "1") == 0, "graceful argument unchanged");
    CHECK(strcmp(wrap_execvp_args[4], "0") == 0, "guest argument unchanged");
    CHECK(strstr(cerr, "event=CLEANUP_START_ERROR ") != NULL,
          "exec failure must be recorded on the child's own stream");
    close(cap[0]);
    close(cap[1]);
    close(sv[1]);
}

static void test_cleanup_fork_failure_logged_as_error(void) {
    struct Client *c;
    int sv[2];
    char out[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, 0);
    mk_client_sockpair(c, sv);
    wrap_fork_ret = -1;

    cleanup_client(c); /* frees the client */

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "<3>vmid=100 ") != NULL, "fork failure is ERROR level");
    CHECK(strstr(out, "event=CLEANUP_START_ERROR ") != NULL, "fork failure recorded");
    CHECK(wrap_execvp_calls == 0, "no exec when fork failed");
    close(sv[1]);
}

static void test_sigkill_fallback_logged(void) {
    struct Client *c;
    time_t past = time(NULL) - 1;
    char out[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, -1);
    c->pidfd = -1;
    c->timeout = past;
    wrap_kill_ret = 0;

    sigkill(c, &past);

    drain_log(out, sizeof(out));
    CHECK(
        strstr(out, "level=warning source=qmeventd event=SIGKILL_FALLBACK ") != NULL,
        "sigkill logged"
    );
    CHECK(wrap_kill_calls == 1 && wrap_kill_last_sig == SIGKILL, "SIGKILL still sent");
    free(c);
}

static void test_sigkill_failure_logged_as_error(void) {
    struct Client *c;
    time_t past = time(NULL) - 1;
    char out[8192];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, -1);
    c->pidfd = -1;
    c->timeout = past;
    wrap_kill_ret = -1;
    wrap_kill_errno = EPERM;

    sigkill(c, &past);

    drain_log(out, sizeof(out));
    CHECK(strncmp(out, "<3>", 3) == 0, "failed SIGKILL is ERROR level");
    CHECK(strstr(out, "event=SIGKILL_FALLBACK ") != NULL, "sigkill failure recorded");
    free(c);
}

static void test_protocol_error_is_suppressed_per_connection(void) {
    struct Client *c;
    int sv[2];
    char out[16384];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, 0);
    mk_client_sockpair(c, sv);

    if (write(sv[1], "not json", 8) != 8) {
        abort();
    }
    handle_client(c);
    if (write(sv[1], "junk2", 5) != 5) {
        abort();
    }
    handle_client(c);

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "event=PROTOCOL_ERROR ") != NULL, "first parse error recorded");
    CHECK(count_lines(out) == 1, "repeated parse errors must be suppressed");

    cleanup_client(c); /* frees the client; must report the suppressed repeats */

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "suppressed") != NULL, "suppressed repeats must be reported on close");
    close(sv[1]);
}

/* ------------------------------------------------------------------ */
/* group 3: delivery robustness (backpressure, closed sink, truncation)*/
/* ------------------------------------------------------------------ */

static size_t drain_fd(int fd, char *out, size_t cap) {
    size_t total = 0;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    for (;;) {
        ssize_t n;
        if (total + 1 >= cap) {
            break;
        }
        n = read(fd, out + total, cap - total - 1);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        break;
    }
    out[total] = '\0';
    return total;
}

static void test_full_sink_is_bounded_and_reported(void) {
    static char sink[1 << 20];
    struct json_object *obj;
    struct qmeventd_log_stats st;
    int sv[2];
    int i;

    logtest_setup();
    base_globals_init();
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }
    qmeventd_log_init(sv[0]); /* never read during the loop */
    qmeventd_log_reset_stats();

    obj = J(
        "{\"event\":\"BLOCK_IO_ERROR\",\"data\":{\"pad\":\"012345678901234567890123456789"
        "0123456789\"}}"
    );
    for (i = 0; i < 20000; i++) {
        qmeventd_log_event("100", 1234, 1234, QLOG_ERROR, "qmp", "BLOCK_IO_ERROR", obj);
    }
    json_object_put(obj);

    qmeventd_log_get_stats(&st);
    CHECK(st.dropped_lines > 0, "a full sink must drop instead of blocking");
    CHECK(st.accepted + st.dropped_lines >= 20000, "every record must be accounted for");

    drain_fd(sv[1], sink, sizeof(sink));
    /* the sink drained: an idle flush and one more record must clear the
     * backlog and report the drops exactly once */
    qmeventd_log_flush_pending();
    qmeventd_log_event("1000", 4321, 4321, QLOG_INFO, "qmp", "STOP", NULL);
    drain_fd(sv[1], sink, sizeof(sink));

    CHECK(strstr(sink, "event=LOG_DROPPED ") != NULL, "dropped records must be reported");
    CHECK(strstr(sink, "vmid=1000 qemu_pid=4321 ") != NULL, "other VM records are unaffected");
    CHECK(st.accepted + st.dropped_lines >= 20000, "accounting must stay consistent");
    close(sv[0]);
    close(sv[1]);
}

static void test_closed_sink_does_not_block_or_crash(void) {
    struct qmeventd_log_stats st;
    int sv[2];

    logtest_setup();
    base_globals_init();
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }
    close(sv[1]); /* reader gone: sends will fail with EPIPE */
    qmeventd_log_init(sv[0]);
    qmeventd_log_reset_stats();

    errno = EAGAIN;
    qmeventd_log_event("100", 1234, 1234, QLOG_INFO, "qmp", "STOP", NULL);
    CHECK(errno == EAGAIN, "logging must preserve the caller's errno");

    qmeventd_log_get_stats(&st);
    CHECK(st.dropped_bytes > 0, "a dead sink must be accounted for");
    close(sv[0]);
}

static void test_oversized_payload_is_truncated_not_corrupted(void) {
    struct json_object *obj;
    struct json_object *data;
    struct qmeventd_log_stats st;
    char *pad = malloc(4096);
    char out[8192];
    int i;

    logtest_setup();
    base_globals_init();
    for (i = 0; i < 4096; i++) {
        pad[i] = 'a';
    }
    obj = json_object_new_object();
    json_object_object_add(obj, "event", json_object_new_string("BLOCK_IO_ERROR"));
    data = json_object_new_object();
    json_object_object_add(data, "pad", json_object_new_string_len(pad, 4095));
    json_object_object_add(obj, "data", data);

    qmeventd_log_event("100", 1234, 1234, QLOG_ERROR, "qmp", "BLOCK_IO_ERROR", obj);
    json_object_put(obj);

    drain_log(out, sizeof(out));
    CHECK(count_lines(out) == 1, "oversized payload must stay one line");
    CHECK(strstr(out, "\"_truncated\":true") != NULL, "an explicit truncation marker is required");
    CHECK(strstr(out, "yyyyy") == NULL, "no fabricated content");
    qmeventd_log_get_stats(&st);
    CHECK(st.truncated == 1, "truncation must be counted");
    free(pad);
}

/* ------------------------------------------------------------------ */
/* group 4: log-layer hardening                                       */
/*                                                                    */
/* The log sink is the daemon's stdout, which systemd always backs    */
/* with an AF_UNIX socket. Anything else (pipe, tty, regular file) is */
/* explicitly unsupported: writing it non-blockingly is impossible    */
/* without touching shared fd state, and a raw write() would raise    */
/* SIGPIPE or block the control loop.                                 */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t sigpipe_seen = 0;
static void test_sigpipe_handler(int sig) {
    (void)sig;
    sigpipe_seen = 1;
}

static void fill_socket_write_buffer(int fd) {
    char junk[16384];
    size_t chunk;
    memset(junk, 'x', sizeof(junk));
    /* shrink the chunk so the buffer ends up truly full (a leftover chunk
     * would let a small record slip through and make the test flaky) */
    for (chunk = sizeof(junk); chunk > 0; chunk >>= 1) {
        while (send(fd, junk, chunk, MSG_DONTWAIT | MSG_NOSIGNAL) > 0) {
        }
    }
}

static void test_untrusted_vmid_cannot_forge_lines(void) {
    char out[8192];

    logtest_setup();
    base_globals_init();
    qmeventd_log_event("100\nFORGED", 101, 101, QLOG_WARNING, "vzdump", "PROTOCOL_ERROR", NULL);
    drain_log(out, sizeof(out));

    CHECK(count_lines(out) == 1, "a newline in the vmid must not forge a second record");
    CHECK(strncmp(out, "<4>", 3) == 0, "the record keeps its warning level");
    CHECK(strstr(out, "vmid=- ") != NULL, "an unsafe vmid must render as a single dash");
    CHECK(strstr(out, "_untrusted_vmid") != NULL, "the raw value must be kept for diagnostics");
    CHECK(strstr(out, "FORGED") != NULL, "the raw value must appear escaped in the payload");
}

static void test_non_socket_sink_is_rejected(void) {
    struct qmeventd_log_stats st;
    struct sigaction sa, old;
    int fds[2];

    logtest_setup();
    base_globals_init();
    if (pipe(fds) != 0) {
        abort();
    }
    close(fds[0]); /* reader gone: a raw write() would raise SIGPIPE */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = test_sigpipe_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGPIPE, &sa, &old);
    qmeventd_log_init(fds[1]);
    qmeventd_log_reset_stats();
    sigpipe_seen = 0;

    qmeventd_log_event("100", 101, 101, QLOG_INFO, "qmp", "STOP", NULL);

    sigaction(SIGPIPE, &old, NULL);
    CHECK(sigpipe_seen == 0, "a non-socket sink must never be written with raw write()");
    qmeventd_log_get_stats(&st);
    CHECK(st.dropped_lines == 1, "the unsupported sink must account the record as dropped");
    close(fds[1]);
}

static jmp_buf block_jmp;
static volatile sig_atomic_t block_alarm = 0;
static void test_alarm_handler(int sig) {
    (void)sig;
    block_alarm = 1;
    longjmp(block_jmp, 1);
}

static void test_full_non_socket_pipe_does_not_block(void) {
    struct qmeventd_log_stats st;
    struct sigaction sa, old;
    char junk[4096];
    int fds[2];

    logtest_setup();
    base_globals_init();
    if (pipe(fds) != 0) {
        abort();
    }
    memset(junk, 'x', sizeof(junk));
    fcntl(fds[1], F_SETFL, O_NONBLOCK);
    while (write(fds[1], junk, sizeof(junk)) > 0) {
    }
    fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL) & ~O_NONBLOCK); /* blocking + full */

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = test_alarm_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, &old);
    qmeventd_log_init(fds[1]);
    qmeventd_log_reset_stats();
    block_alarm = 0;

    if (setjmp(block_jmp) == 0) {
        alarm(5);
        qmeventd_log_event("100", 101, 101, QLOG_INFO, "qmp", "STOP", NULL);
        alarm(0);
    } else {
        sigaction(SIGALRM, &old, NULL);
        tests_failed++;
        fprintf(stderr, "FAIL %s:%d: logging blocked on a full non-socket pipe\n", __FILE__, __LINE__);
        close(fds[0]);
        close(fds[1]);
        return;
    }
    sigaction(SIGALRM, &old, NULL);
    CHECK(block_alarm == 0, "logging must not block on a full non-socket pipe");
    qmeventd_log_get_stats(&st);
    CHECK(st.dropped_lines == 1, "the full unsupported pipe must account the record as dropped");
    close(fds[0]);
    close(fds[1]);
}

static void test_dead_socket_accounts_undelivered_records(void) {
    struct qmeventd_log_stats st;
    int sv[2];

    logtest_setup();
    base_globals_init();
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }
    {
        int small = 8192;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    }
    qmeventd_log_init(sv[0]);
    qmeventd_log_reset_stats();
    fill_socket_write_buffer(sv[0]);
    CHECK(send(sv[0], "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL) < 0,
          "the fixture must start from a full sink");

    qmeventd_log_event("100", 101, 101, QLOG_INFO, "qmp", "STOP", NULL);
    qmeventd_log_event("100", 101, 101, QLOG_INFO, "qmp", "RESUME", NULL);
    qmeventd_log_event("100", 101, 101, QLOG_INFO, "qmp", "RESET", NULL);
    close(sv[1]); /* the sink dies while the queue is non-empty */

    errno = EAGAIN;
    qmeventd_log_event("100", 101, 101, QLOG_INFO, "qmp", "RESET", NULL);
    CHECK(errno == EAGAIN, "errno must survive a dead sink");

    qmeventd_log_get_stats(&st);
    CHECK(st.delivered == 0, "nothing could be delivered while the buffer was full");
    CHECK(st.accepted == st.dropped_lines,
          "a hard error must account every accepted record as dropped, never as success");
    CHECK(st.dropped_lines == 4, "all four queued records must be counted, not cleared silently");
    CHECK(st.dropped_bytes > 0, "the dropped bytes must be counted");
    close(sv[0]);
}

static void test_idle_flush_recovers_without_a_new_event(void) {
    struct qmeventd_log_stats st;
    static char sink[1 << 20];
    char out[65536];
    int sv[2];
    int i;

    logtest_setup();
    base_globals_init();
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }
    {
        int small = 8192;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    }
    qmeventd_log_init(sv[0]);
    qmeventd_log_reset_stats();
    fill_socket_write_buffer(sv[0]);
    for (i = 0; i < 300; i++) {
        qmeventd_log_event("200", 101, 101, QLOG_ERROR, "qmp", "BLOCK_IO_ERROR", NULL);
    }
    qmeventd_log_get_stats(&st);
    CHECK(st.dropped_lines > 0, "the full sink must have produced visible drops");

    (void)drain_fd(sv[1], sink, sizeof(sink)); /* the journal recovers: no new VM event */
    qmeventd_log_flush_pending();
    memset(out, 0, sizeof(out));
    (void)drain_fd(sv[1], out, sizeof(out));

    CHECK(strstr(out, "event=LOG_DROPPED ") != NULL, "drops must be reported once the sink recovers");
    CHECK(strstr(out, "\"lines\":") != NULL, "the drop summary must carry the record count");
    CHECK(strstr(out, "\"first_s\":") != NULL, "the drop summary must carry the first drop time");
    CHECK(strstr(out, "\"last_s\":") != NULL, "the drop summary must carry the last drop time");

    memset(out, 0, sizeof(out));
    qmeventd_log_flush_pending();
    (void)drain_fd(sv[1], out, sizeof(out));
    CHECK(out[0] == '\0', "a delivered drop summary must be cleared, not repeated");
    close(sv[0]);
    close(sv[1]);
}

static void test_owner_quota_reserves_space_for_another_vm(void) {
    static char sink[1 << 20];
    char out[65536];
    struct qmeventd_log_stats st;
    int sv[2];
    int i;

    logtest_setup();
    base_globals_init();
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }
    {
        int small = 8192;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    }
    qmeventd_log_init(sv[0]);
    qmeventd_log_reset_stats();
    fill_socket_write_buffer(sv[0]);
    for (i = 0; i < 2000; i++) {
        qmeventd_log_event("200", 101, 101, QLOG_ERROR, "qmp", "BLOCK_IO_ERROR", NULL);
    }
    qmeventd_log_event("100", 102, 102, QLOG_INFO, "qmp", "STOP", NULL);
    qmeventd_log_get_stats(&st);
    CHECK(st.dropped_lines > 0, "the storming VM must hit its quota visibly");

    (void)drain_fd(sv[1], sink, sizeof(sink));
    qmeventd_log_flush_pending();
    memset(out, 0, sizeof(out));
    (void)drain_fd(sv[1], out, sizeof(out));
    CHECK(strstr(out, "vmid=100 qemu_pid=102 ") != NULL,
          "the other VM must not be starved by the storm");
    CHECK(strstr(out, "event=STOP") != NULL, "the other VM's event must be delivered");
    close(sv[0]);
    close(sv[1]);
}

/* ------------------------------------------------------------------ */
/* group 5: log context, per-connection throttling, storm isolation   */
/* ------------------------------------------------------------------ */

static size_t drain_fd(int fd, char *out, size_t cap); /* defined in group 3 */

static int count_substr(const char *s, const char *sub) {
    int n = 0;
    size_t l = strlen(sub);
    const char *p = s;
    while (l > 0 && (p = strstr(p, sub)) != NULL) {
        n++;
        p += l;
    }
    return n;
}

static void test_qmp_event_storm_is_bounded_per_connection(void) {
    struct Client *a;
    struct json_object *err;
    int sva[2];
    static char sink[1 << 20];
    char out[65536];
    int i, delivered;

    logtest_setup();
    base_globals_init();
    a = mk_client(CLIENT_QEMU, "200", 2001, 0);
    mk_client_sockpair(a, sva);
    qmeventd_log_init(log_wfd);
    qmeventd_log_reset_stats();

    err = J("{\"event\":\"BLOCK_IO_ERROR\",\"data\":{\"x\":1}}");
    for (i = 0; i < 5000; i++) {
        handle_qmp_event(a, err);
    }
    (void)drain_fd(log_rfd, sink, sizeof(sink));
    qmeventd_log_flush_pending();
    memset(out, 0, sizeof(out));
    (void)drain_fd(log_rfd, out, sizeof(out));

    delivered = count_substr(sink, "event=BLOCK_IO_ERROR") +
                count_substr(out, "event=BLOCK_IO_ERROR");
    CHECK(delivered <= 400, "one connection's whitelisted storm must be bounded");
    CHECK(strstr(sink, "LOG_SUPPRESSED") != NULL || strstr(out, "LOG_SUPPRESSED") != NULL,
          "the suppressed storm must be reported visibly");

    json_object_put(err);
    free(a);
    close(sva[1]);
}

static void test_vzdump_protocol_error_uses_mapped_qemu_pid(void) {
    struct Client *q;
    struct Client *v;
    struct json_object *obj;
    int svq[2];
    int svv[2];
    char out[8192];

    logtest_setup();
    base_globals_init();
    q = mk_client(CLIENT_QEMU, "100", 1234, 0);
    mk_client_sockpair(q, svq);
    g_hash_table_insert(vm_clients, strdup("100"), q);

    v = mk_client(CLIENT_NONE, NULL, 5555, 0);
    mk_client_sockpair(v, svv);
    v->state = STATE_HANDSHAKE;
    obj = J("{\"vmid\":\"100\"}");
    handle_vzdump_handshake(v, obj);
    json_object_put(obj);
    drain_log(out, sizeof(out)); /* discard the guard-enter record */

    if (write(svv[1], "not json", 8) != 8) {
        abort();
    }
    handle_client(v); /* VZDUMP connection: a protocol error must not claim its pid as QEMU */

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "source=vzdump event=PROTOCOL_ERROR ") != NULL, "vzdump proto error recorded");
    CHECK(strstr(out, "qemu_pid=1234 peer_pid=5555 ") != NULL,
          "the VZDump peer pid must never be reported as the QEMU pid");
    close(svq[1]);
    close(svv[1]);
    free(v);
    free(q);
}

static void test_vzdump_invalid_handshakes_are_throttled(void) {
    struct Client *v;
    struct json_object *obj;
    int svv[2];
    char out[8192];
    int i;

    logtest_setup();
    base_globals_init();
    v = mk_client(CLIENT_NONE, NULL, 5555, 0);
    mk_client_sockpair(v, svv);
    obj = J("{\"vmid\":\"999\"}"); /* unregistered VM */
    for (i = 0; i < 5; i++) {
        v->state = STATE_HANDSHAKE;
        handle_vzdump_handshake(v, obj);
    }
    json_object_put(obj);

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "source=vzdump event=PROTOCOL_ERROR ") != NULL, "vzdump proto error recorded");
    CHECK(count_lines(out) == 1, "repeated invalid handshakes must be throttled per connection");

    cleanup_client(v); /* frees the client; reports the suppressed repeats */

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "suppressed") != NULL, "suppressed handshakes must be summarised on close");
    close(svv[1]);
}

static void test_protocol_summary_well_before_thousand(void) {
    struct Client *c;
    int sv[2];
    char out[65536];
    int i;

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, 0);
    mk_client_sockpair(c, sv);

    for (i = 0; i < 300; i++) {
        if (write(sv[1], "junk", 4) != 4) {
            abort();
        }
        handle_client(c);
    }

    memset(out, 0, sizeof(out));
    drain_log(out, sizeof(out));
    CHECK(strstr(out, "event=PROTOCOL_ERROR ") != NULL, "the first protocol error is recorded");
    CHECK(strstr(out, "\"suppressed\":") != NULL,
          "a suppressed summary must appear well before 1000 repeats");
    CHECK(strstr(out, "\"first_s\":") != NULL, "the summary must carry the first error time");
    CHECK(count_lines(out) <= 6, "protocol error output must stay bounded");
    cleanup_client(c);
    close(sv[1]);
}

static void test_one_vm_storm_does_not_starve_another(void) {
    struct Client *a;
    struct Client *b;
    struct json_object *err;
    struct json_object *stop;
    struct json_object *resume;
    int sva[2];
    int svb[2];
    static char sink[1 << 20];
    char out[65536];
    int i;

    logtest_setup();
    base_globals_init();
    a = mk_client(CLIENT_QEMU, "200", 2001, 0);
    mk_client_sockpair(a, sva);
    b = mk_client(CLIENT_QEMU, "100", 1001, 0);
    mk_client_sockpair(b, svb);
    {
        int small = 8192;
        setsockopt(log_wfd, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    }
    qmeventd_log_init(log_wfd);
    qmeventd_log_reset_stats();

    err = J("{\"event\":\"BLOCK_IO_ERROR\",\"data\":{\"x\":1}}");
    for (i = 0; i < 5000; i++) {
        handle_qmp_event(a, err);
    }
    /* VM A's storm is still in flight: VM B logs while the sink is full */
    stop = J("{\"event\":\"STOP\"}");
    handle_qmp_event(b, stop);

    /* the journal recovers; a later VM B event must flush the backlog */
    (void)drain_fd(log_rfd, sink, sizeof(sink));
    resume = J("{\"event\":\"RESUME\"}");
    handle_qmp_event(b, resume);
    memset(out, 0, sizeof(out));
    (void)drain_fd(log_rfd, out, sizeof(out));

    CHECK(strstr(out, "vmid=100 qemu_pid=1001 ") != NULL, "VM B must not be starved by VM A");
    CHECK(strstr(out, "event=STOP") != NULL, "VM B's event logged during the storm must survive");

    json_object_put(err);
    json_object_put(stop);
    json_object_put(resume);
    free(a);
    free(b);
    close(sva[1]);
    close(svb[1]);
}

static void test_cleanup_child_does_not_resend_parent_queue(void) {
    struct Client *c;
    int sv[2];
    int cap[2];
    int saved2;
    char out[16384];
    char cout[8192];
    static char junk[1 << 20];

    logtest_setup();
    base_globals_init();
    c = mk_client(CLIENT_QEMU, "100", 1234, 0);
    mk_client_sockpair(c, sv);
    {
        int small = 8192;
        setsockopt(log_wfd, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    }
    fill_socket_write_buffer(log_wfd); /* the next parent record stays queued */
    qmeventd_log_event("100", 1234, 1234, QLOG_INFO, "qmeventd", "PENDING_MARKER", NULL);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, cap) != 0) {
        abort();
    }
    saved2 = dup(STDERR_FILENO);
    (void)dup2(cap[0], STDERR_FILENO); /* the child's independent journal stream */

    wrap_fork_ret = 0; /* take the child branch */
    wrap_exit_seen = 0;
    wrap_exit_status = -1;
    exec_landing = setjmp(exec_jmp);
    if (exec_landing == 0) {
        cleanup_client(c); /* child branch: execvp fails, logs, then _exit(1) */
        CHECK(0, "cleanup child branch must not return");
    }

    (void)dup2(saved2, STDERR_FILENO);
    close(saved2);

    (void)drain_fd(log_rfd, junk, sizeof(junk)); /* discard the filler */
    memset(out, 0, sizeof(out));
    (void)drain_fd(log_rfd, out, sizeof(out));
    drain_fd(cap[1], cout, sizeof(cout));

    /*
     * The wrapped fork() shares globals with the "child", so the parent-side
     * copy of the queue cannot be modelled here (a real fork() duplicates it;
     * that path is exercised on the test node). What is verified is the child
     * side: it must log on its own stream, keep the known identity, drop the
     * inherited queue instead of resending it, and exit with a failure status.
     */
    CHECK(wrap_exit_seen == 1, "the child must really _exit(), never return success");
    CHECK(wrap_exit_status == 1, "the cleanup child must exit with a failure status");
    CHECK(strstr(cout, "event=CLEANUP_START_ERROR ") != NULL,
          "the exec failure must be logged on the independent stream");
    CHECK(strstr(cout, "vmid=100 qemu_pid=1234 ") != NULL,
          "the child must keep the known VMID and QEMU pid");
    CHECK(strstr(cout, "PENDING_MARKER") == NULL,
          "the child must not resend the parent's queued records");
    CHECK(strstr(cout, "event=QMP_DISCONNECTED") == NULL &&
              strstr(cout, "event=CLEANUP_REQUESTED") == NULL,
          "the child must not resend any inherited queued record");
    CHECK(strstr(out, "event=CLEANUP_START_ERROR") == NULL,
          "the child error must not appear on the parent's stream");

    /* The wrapped _exit() longjmps past cleanup_client's normal free(). */
    free(c);
    close(sv[1]);
    close(cap[0]);
    close(cap[1]);
}

/* ------------------------------------------------------------------ */
/* group 6: drop-summary snapshot/ack + child accounting              */
/*                                                                    */
/* A drop summary is a single in-flight snapshot: the live drop win-  */
/* dow is moved into it when the record is enqueued, and it is acked  */
/* only once the record is fully written (or restored when the sink   */
/* fails). These tests pin the exact-once / no-loss / per-window      */
/* properties of that state machine.                                  */
/* ------------------------------------------------------------------ */

static void test_hard_failure_then_rebind_reports_once(void) {
    char out[65536];
    struct qmeventd_log_stats st;
    int sv[2];
    int sv2[2];
    int i;

    logtest_setup();
    base_globals_init();
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }
    qmeventd_log_init(sv[0]);
    close(sv[1]); /* reader gone: the first send fails hard (EPIPE) */
    qmeventd_log_event("100", 101, 101, QLOG_INFO, "qmp", "STOP", NULL);

    CHECK(!qmeventd_log_has_pending(), "a dead sink must not arm idle wakeups");
    qmeventd_log_get_stats(&st);
    CHECK(st.accepted == 1 && st.delivered == 0 && st.dropped_lines == 1,
          "the undeliverable record must be accounted as dropped, never as success");

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) != 0) {
        abort();
    }
    qmeventd_log_init(sv2[0]); /* explicit rebind re-enables the sink */
    for (i = 0; i < 5; i++) {
        qmeventd_log_flush_pending();
    }
    memset(out, 0, sizeof(out));
    (void)drain_fd(sv2[1], out, sizeof(out));
    CHECK(count_substr(out, "event=LOG_DROPPED ") == 1,
          "the preserved drop window must be reported exactly once after rebind");
    CHECK(strstr(out, "\"lines\":1,") != NULL, "the report must carry the lost record");

    memset(out, 0, sizeof(out));
    qmeventd_log_flush_pending();
    (void)drain_fd(sv2[1], out, sizeof(out));
    CHECK(out[0] == '\0', "a delivered summary must not be repeated");
    CHECK(!qmeventd_log_has_pending(), "nothing may stay pending after the report");
    close(sv[0]);
    close(sv2[0]);
    close(sv2[1]);
}

static void test_summary_eagain_delivered_exactly_once(void) {
    static char sink[1 << 20];
    char out[65536];
    struct qmeventd_log_stats st;
    int sv[2];

    logtest_setup();
    base_globals_init();
    qmeventd_log_init(-1);
    qmeventd_log_event("100", 101, 101, QLOG_INFO, "qmp", "STOP", NULL); /* live drop */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }
    {
        int small = 8192;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    }
    qmeventd_log_init(sv[0]);
    fill_socket_write_buffer(sv[0]); /* the summary cannot be sent yet */
    qmeventd_log_flush_pending();    /* enqueue the summary, send returns EAGAIN */
    CHECK(qmeventd_log_has_pending(), "the undelivered summary must stay pending");

    (void)drain_fd(sv[1], sink, sizeof(sink)); /* the journal recovers */
    memset(out, 0, sizeof(out));
    qmeventd_log_flush_pending(); /* deliver the queued summary */
    (void)drain_fd(sv[1], out, sizeof(out));
    CHECK(count_substr(out, "event=LOG_DROPPED ") == 1,
          "the queued summary must be delivered exactly once, not repeated");

    memset(out, 0, sizeof(out));
    qmeventd_log_flush_pending();
    (void)drain_fd(sv[1], out, sizeof(out));
    CHECK(out[0] == '\0', "a delivered summary must be acknowledged, not re-sent");
    CHECK(!qmeventd_log_has_pending(), "delivery must clear the pending state");
    qmeventd_log_get_stats(&st);
    CHECK(st.dropped_lines == 1, "the drop must be counted exactly once");
    close(sv[0]);
    close(sv[1]);
}

static void test_child_reset_discards_inherited_drop_window(void) {
    char out[8192];
    struct qmeventd_log_stats st;
    int sv[2];
    int i;

    logtest_setup();
    base_globals_init();
    qmeventd_log_init(-1);
    qmeventd_log_event("100", 101, 101, QLOG_INFO, "qmp", "STOP", NULL); /* parent drop */
    qmeventd_log_get_stats(&st);
    CHECK(st.dropped_lines == 1, "the parent drop must be counted");

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }
    qmeventd_log_child_reset(sv[0]); /* the child starts from a clean slate */
    for (i = 0; i < 3; i++) {
        qmeventd_log_flush_pending();
    }
    (void)drain_fd(sv[1], out, sizeof(out));
    CHECK(out[0] == '\0', "the child must not re-emit the parent's drop summary");
    qmeventd_log_get_stats(&st);
    CHECK(st.dropped_lines == 0 && st.accepted == 0 && st.delivered == 0,
          "the child's counters must start at zero");
    close(sv[0]);
    close(sv[1]);
}

static void test_new_drops_while_summary_inflight_are_separate(void) {
    static char collected[1 << 20];
    char tmp[65536];
    char want[64];
    struct qmeventd_log_stats st;
    long long b;
    size_t clen = 0;
    int sv[2];
    int i;
    int guard;

    logtest_setup();
    base_globals_init();
    qmeventd_log_init(-1);
    qmeventd_log_event("100", 101, 101, QLOG_INFO, "qmp", "STOP", NULL); /* drop A */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }
    {
        int small = 8192;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    }
    qmeventd_log_init(sv[0]);
    fill_socket_write_buffer(sv[0]);
    qmeventd_log_flush_pending(); /* summary A (lines=1) queued, send EAGAIN */
    CHECK(qmeventd_log_has_pending(), "summary A must be in flight");

    /* drops that happen while A is in flight must not join or erase A's window */
    for (i = 0; i < 2000; i++) {
        qmeventd_log_event("200", 201, 201, QLOG_ERROR, "qmp", "BLOCK_IO_ERROR", NULL);
    }
    qmeventd_log_get_stats(&st);
    CHECK(st.dropped_lines > 1, "new drops must accrue separately while A is in flight");
    b = (long long)st.dropped_lines - 1;

    collected[0] = '\0';
    for (guard = 0; guard < 128 && qmeventd_log_has_pending(); guard++) {
        size_t n = drain_fd(sv[1], tmp, sizeof(tmp));
        if (n && clen + n < sizeof(collected)) {
            memcpy(collected + clen, tmp, n);
            clen += n;
            collected[clen] = '\0';
        }
        qmeventd_log_flush_pending();
    }
    {
        size_t n = drain_fd(sv[1], tmp, sizeof(tmp));
        if (n && clen + n < sizeof(collected)) {
            memcpy(collected + clen, tmp, n);
            clen += n;
            collected[clen] = '\0';
        }
    }

    CHECK(count_substr(collected, "event=LOG_DROPPED ") == 2,
          "exactly two disjoint summaries must be reported");
    CHECK(strstr(collected, "\"lines\":1,") != NULL,
          "summary A must report exactly its single drop");
    snprintf(want, sizeof(want), "\"lines\":%lld,", b);
    CHECK(strstr(collected, want) != NULL,
          "summary B must report exactly the drops that happened while A was in flight");
    close(sv[0]);
    close(sv[1]);
}

static void test_failure_while_summary_inflight_restores_all(void) {
    char out[65536];
    struct qmeventd_log_stats st;
    int sv[2];
    int sv2[2];
    int i;

    logtest_setup();
    base_globals_init();
    qmeventd_log_init(-1);
    qmeventd_log_event("100", 101, 101, QLOG_INFO, "qmp", "STOP", NULL); /* drop A */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }
    {
        int small = 8192;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    }
    qmeventd_log_init(sv[0]);
    fill_socket_write_buffer(sv[0]);
    qmeventd_log_flush_pending(); /* summary A queued, in flight */
    CHECK(qmeventd_log_has_pending(), "summary A must be in flight");
    /* a record queued behind the summary must also be accounted on failure */
    qmeventd_log_event("100", 101, 101, QLOG_INFO, "qmp", "RESUME", NULL);

    close(sv[1]);                 /* the sink dies while the summary is in flight */
    qmeventd_log_flush_pending(); /* hard error: restore + account + mark dead */
    CHECK(!qmeventd_log_has_pending(), "a dead sink must not keep arming idle wakeups");
    qmeventd_log_get_stats(&st);
    CHECK(st.dropped_lines == 2,
          "the in-flight summary and the queued record must both be accounted, without loss");

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) != 0) {
        abort();
    }
    qmeventd_log_init(sv2[0]); /* explicit rebind */
    for (i = 0; i < 5; i++) {
        qmeventd_log_flush_pending();
    }
    memset(out, 0, sizeof(out));
    (void)drain_fd(sv2[1], out, sizeof(out));
    CHECK(count_substr(out, "event=LOG_DROPPED ") == 1,
          "the restored window must be reported exactly once");
    CHECK(strstr(out, "\"lines\":2,") != NULL,
          "no loss: both restored drops must appear in the one summary");
    CHECK(!qmeventd_log_has_pending(), "nothing may stay pending after the rebind");
    close(sv[0]);
    close(sv2[0]);
    close(sv2[1]);
}

static void test_daemon_wait_timeout_bounds_idle_flush(void) {
    int sv[2];

    logtest_setup();
    base_globals_init();
    needs_cleanup = 0;
    CHECK(daemon_wait_timeout_ms() == -1, "an idle daemon with no work must block indefinitely");

    needs_cleanup = 1;
    CHECK(daemon_wait_timeout_ms() == 10000, "a forced-cleanup deadline keeps its original 10s wait");

    qmeventd_log_init(-1);
    qmeventd_log_event("100", 101, 101, QLOG_INFO, "qmp", "STOP", NULL); /* real drop backlog */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }
    qmeventd_log_init(sv[0]);
    CHECK(qmeventd_log_has_pending(), "a drop backlog must be pending");
    CHECK(daemon_wait_timeout_ms() == 200,
          "a pending log backlog must shorten a 10s cleanup wait to 200ms");
    needs_cleanup = 0;
    CHECK(daemon_wait_timeout_ms() == 200, "an idle log backlog must wait only 200ms");
    close(sv[0]);
    close(sv[1]);
}

/* ------------------------------------------------------------------ */
/* group 7: daemon <-> capture-worker wiring                          */
/* ------------------------------------------------------------------ */

static void test_handshake_forwards_connected_observation(void) {
    struct Client *c;
    int sv[2];
    char pkt[8192];
    struct json_object *o;

    logtest_setup();
    base_globals_init();
    capture_install();
    set_fake_cmdline_vmid(100);
    set_fake_stat(1234, "777000");
    c = mk_client(CLIENT_QEMU, NULL, 1234, 0);
    mk_client_sockpair(c, sv);
    c->state = STATE_HANDSHAKE;

    handle_qmp_handshake(c);

    CHECK(cap_spawn_calls == 1, "the first trusted identity lazily starts the worker");
    CHECK(cap_recv(pkt, sizeof(pkt)) > 0, "a connected observation must be forwarded");
    o = json_tokener_parse(pkt);
    CHECK(o != NULL, "the observation must be valid JSON");
    CHECK(!strcmp(cap_jstr(o, "op"), "observe"), "op observe");
    CHECK(!strcmp(cap_jstr(o, "kind"), "connected"), "kind connected");
    CHECK(cap_jint(o, "vmid") == 100 && cap_jint(o, "pid") == 1234, "trusted identity carried");
    CHECK(cap_jstr(o, "starttime") && !strcmp(cap_jstr(o, "starttime"), "777000"),
          "starttime read from /proc");
    CHECK(cap_jint(o, "generation") == 1, "a new connection starts at generation 1");
    json_object_put(o);
    capture_uninstall();
    close(sv[0]);
    close(sv[1]);
    free(c);
}

static void test_reset_forwards_event_and_advances_generation(void) {
    struct Client *c;
    struct json_object *obj;
    struct json_object *o;
    struct json_object *ev;
    int sv[2];
    char pkt[8192];

    logtest_setup();
    base_globals_init();
    capture_install();
    set_fake_cmdline_vmid(100);
    set_fake_stat(1234, "777000");
    c = mk_client(CLIENT_QEMU, NULL, 1234, 0);
    mk_client_sockpair(c, sv);
    c->state = STATE_HANDSHAKE;
    handle_qmp_handshake(c);
    (void)cap_recv(pkt, sizeof(pkt)); /* connected */

    obj = J("{\"event\":\"RESET\"}");
    handle_qmp_event(c, obj);
    json_object_put(obj);

    CHECK(cap_recv(pkt, sizeof(pkt)) > 0, "RESET must be forwarded to the worker");
    o = json_tokener_parse(pkt);
    CHECK(o && !strcmp(cap_jstr(o, "kind"), "event"), "kind event");
    CHECK(o && json_object_object_get_ex(o, "event", &ev) &&
              !strcmp(cap_jstr(ev, "event"), "RESET"),
          "the full RESET event is forwarded");
    CHECK(cap_jint(o, "generation") == 2, "a guest RESET advances the generation");
    CHECK(qmev_capture_generation(capture_mod, "100") == 2, "registry generation advanced");
    json_object_put(o);
    capture_uninstall();
    close(sv[0]);
    close(sv[1]);
    free(c);
}

static void test_crashloaded_is_forwarded_and_journaled(void) {
    struct Client *c;
    struct json_object *obj;
    struct json_object *o;
    struct json_object *ev;
    int sv[2];
    char pkt[8192];
    char out[8192];

    logtest_setup();
    base_globals_init();
    capture_install();
    set_fake_cmdline_vmid(100);
    set_fake_stat(1234, "777000");
    c = mk_client(CLIENT_QEMU, NULL, 1234, 0);
    mk_client_sockpair(c, sv);
    c->state = STATE_HANDSHAKE;
    handle_qmp_handshake(c);
    (void)cap_recv(pkt, sizeof(pkt));
    drain_log(out, sizeof(out)); /* discard the handshake record */

    obj = J("{\"event\":\"GUEST_CRASHLOADED\",\"data\":{\"reason\":\"dump\"}}");
    handle_qmp_event(c, obj);
    json_object_put(obj);

    CHECK(cap_recv(pkt, sizeof(pkt)) > 0, "CRASHLOADED must be forwarded to the worker");
    o = json_tokener_parse(pkt);
    CHECK(o && json_object_object_get_ex(o, "event", &ev) &&
              !strcmp(cap_jstr(ev, "event"), "GUEST_CRASHLOADED"),
          "the full CRASHLOADED event is forwarded");
    json_object_put(o);

    drain_log(out, sizeof(out));
    CHECK(strstr(out, "level=error source=qmp event=GUEST_CRASHLOADED ") != NULL,
          "CRASHLOADED must also be journaled at ERROR independently");
    capture_uninstall();
    close(sv[0]);
    close(sv[1]);
    free(c);
}

static void test_disconnect_forwards_disconnected_before_cleanup(void) {
    struct Client *c;
    struct json_object *o;
    int sv[2];
    char pkt[8192];

    logtest_setup();
    base_globals_init();
    capture_install();
    set_fake_cmdline_vmid(100);
    set_fake_stat(1234, "777000");
    c = mk_client(CLIENT_QEMU, NULL, 1234, 0);
    mk_client_sockpair(c, sv);
    c->state = STATE_HANDSHAKE;
    handle_qmp_handshake(c);
    (void)cap_recv(pkt, sizeof(pkt));

    cleanup_client(c); /* frees c */

    CHECK(cap_recv(pkt, sizeof(pkt)) > 0, "disconnect must be forwarded");
    o = json_tokener_parse(pkt);
    CHECK(o && !strcmp(cap_jstr(o, "kind"), "disconnected"), "kind disconnected");
    CHECK(o && cap_jint(o, "pid") == 1234 && cap_jint(o, "generation") == 1, "identity carried");
    json_object_put(o);
    CHECK(qmev_capture_generation(capture_mod, "100") == 0, "identity forgotten on disconnect");
    capture_uninstall();
    close(sv[1]);
}

static void test_backup_guard_forwards_backup_observation(void) {
    struct Client *q;
    struct Client *v;
    struct json_object *obj;
    struct json_object *o;
    struct json_object *b;
    int svq[2];
    int svv[2];
    char pkt[8192];

    logtest_setup();
    base_globals_init();
    capture_install();
    set_fake_cmdline_vmid(100);
    set_fake_stat(1234, "777000");

    q = mk_client(CLIENT_QEMU, NULL, 1234, 0);
    mk_client_sockpair(q, svq);
    q->state = STATE_HANDSHAKE;
    handle_qmp_handshake(q); /* registers the QEMU identity in the capture registry */
    (void)cap_recv(pkt, sizeof(pkt));

    v = mk_client(CLIENT_NONE, NULL, 5555, 0);
    mk_client_sockpair(v, svv);
    v->state = STATE_HANDSHAKE;
    obj = J("{\"vmid\":\"100\"}");
    handle_vzdump_handshake(v, obj);
    json_object_put(obj);

    CHECK(cap_recv(pkt, sizeof(pkt)) > 0, "backup enter must be forwarded");
    o = json_tokener_parse(pkt);
    CHECK(o && !strcmp(cap_jstr(o, "kind"), "backup"), "kind backup");
    CHECK(o && cap_jint(o, "pid") == 1234 && cap_jint(o, "generation") == 1,
          "the observation maps to the QEMU identity, never the helper PID");
    CHECK(o && json_object_object_get_ex(o, "backup", &b) && json_object_get_boolean(b) == 1,
          "backup=true");
    json_object_put(o);

    cleanup_client(v); /* frees v */

    CHECK(cap_recv(pkt, sizeof(pkt)) > 0, "backup leave must be forwarded");
    o = json_tokener_parse(pkt);
    CHECK(o && json_object_object_get_ex(o, "backup", &b) && json_object_get_boolean(b) == 0,
          "backup=false");
    json_object_put(o);

    capture_uninstall();
    close(svq[1]);
    close(svv[1]);
    free(q);
}

int main(void) {
    struct {
        const char *name;
        void (*fn)(void);
    } tests[] = {
        {"qmp_stop_event_is_logged", test_qmp_stop_event_is_logged},
        {"priority_prefix_is_pure_severity", test_priority_prefix_is_pure_severity},
        {"unknown_event_is_not_logged", test_unknown_event_is_not_logged},
        {"error_events_are_logged_at_error_level", test_error_events_are_logged_at_error_level},
        {"guest_crashloaded_is_logged_at_error_level",
         test_guest_crashloaded_is_logged_at_error_level},
        {"watchdog_is_logged_at_warning_level", test_watchdog_is_logged_at_warning_level},
        {"logged_before_terminating_early_return", test_logged_before_terminating_early_return},
        {"shutdown_keeps_guest_and_reason", test_shutdown_keeps_guest_and_reason},
        {"payload_cannot_inject_newlines", test_payload_cannot_inject_newlines},
        {"vmid_not_confused_between_clients", test_vmid_not_confused_between_clients},
        {"qmp_connected_on_handshake", test_qmp_connected_on_handshake},
        {"qmp_handshake_failure_logged_as_protocol_error",
         test_qmp_handshake_failure_logged_as_protocol_error},
        {"qmp_disconnected_and_cleanup_requested", test_qmp_disconnected_and_cleanup_requested},
        {"backup_guard_enter_and_leave", test_backup_guard_enter_and_leave},
        {"vzdump_unregistered_vmid_is_protocol_error",
         test_vzdump_unregistered_vmid_is_protocol_error},
        {"vm_status_changed_logged_once", test_vm_status_changed_logged_once},
        {"termination_deferred_logged_once", test_termination_deferred_logged_once},
        {"qmp_error_logged", test_qmp_error_logged},
        {"quit_requested_and_sigterm_fallback", test_quit_requested_and_sigterm_fallback},
        {"cleanup_requested_preserves_exec_arguments",
         test_cleanup_requested_preserves_exec_arguments},
        {"cleanup_fork_failure_logged_as_error", test_cleanup_fork_failure_logged_as_error},
        {"sigkill_fallback_logged", test_sigkill_fallback_logged},
        {"sigkill_failure_logged_as_error", test_sigkill_failure_logged_as_error},
        {"protocol_error_is_suppressed_per_connection",
         test_protocol_error_is_suppressed_per_connection},
        {"full_sink_is_bounded_and_reported", test_full_sink_is_bounded_and_reported},
        {"closed_sink_does_not_block_or_crash", test_closed_sink_does_not_block_or_crash},
        {"oversized_payload_is_truncated_not_corrupted",
         test_oversized_payload_is_truncated_not_corrupted},
        {"untrusted_vmid_cannot_forge_lines", test_untrusted_vmid_cannot_forge_lines},
        {"non_socket_sink_is_rejected", test_non_socket_sink_is_rejected},
        {"full_non_socket_pipe_does_not_block", test_full_non_socket_pipe_does_not_block},
        {"dead_socket_accounts_undelivered_records",
         test_dead_socket_accounts_undelivered_records},
        {"idle_flush_recovers_without_a_new_event", test_idle_flush_recovers_without_a_new_event},
        {"owner_quota_reserves_space_for_another_vm",
         test_owner_quota_reserves_space_for_another_vm},
        {"vzdump_protocol_error_uses_mapped_qemu_pid",
         test_vzdump_protocol_error_uses_mapped_qemu_pid},
        {"vzdump_invalid_handshakes_are_throttled", test_vzdump_invalid_handshakes_are_throttled},
        {"protocol_summary_well_before_thousand", test_protocol_summary_well_before_thousand},
        {"qmp_event_storm_is_bounded_per_connection",
         test_qmp_event_storm_is_bounded_per_connection},
        {"one_vm_storm_does_not_starve_another", test_one_vm_storm_does_not_starve_another},
        {"cleanup_child_does_not_resend_parent_queue",
         test_cleanup_child_does_not_resend_parent_queue},
        {"hard_failure_then_rebind_reports_once", test_hard_failure_then_rebind_reports_once},
        {"summary_eagain_delivered_exactly_once", test_summary_eagain_delivered_exactly_once},
        {"child_reset_discards_inherited_drop_window",
         test_child_reset_discards_inherited_drop_window},
        {"new_drops_while_summary_inflight_are_separate",
         test_new_drops_while_summary_inflight_are_separate},
        {"failure_while_summary_inflight_restores_all",
         test_failure_while_summary_inflight_restores_all},
        {"daemon_wait_timeout_bounds_idle_flush", test_daemon_wait_timeout_bounds_idle_flush},
        {"handshake_forwards_connected_observation",
         test_handshake_forwards_connected_observation},
        {"reset_forwards_event_and_advances_generation",
         test_reset_forwards_event_and_advances_generation},
        {"crashloaded_is_forwarded_and_journaled", test_crashloaded_is_forwarded_and_journaled},
        {"disconnect_forwards_disconnected_before_cleanup",
         test_disconnect_forwards_disconnected_before_cleanup},
        {"backup_guard_forwards_backup_observation",
         test_backup_guard_forwards_backup_observation},
    };
    size_t i;
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        tests_run++;
        fprintf(stderr, "RUN %s\n", tests[i].name);
        tests[i].fn();
    }
    fprintf(stderr, "qmeventd log tests: %d run, %d failed\n", tests_run, tests_failed);
    if (log_rfd >= 0) {
        close(log_rfd);
        close(log_wfd);
    }
    return tests_failed ? 1 : 0;
}
