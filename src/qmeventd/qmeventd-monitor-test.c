// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    Unit tests for the qmeventd monitor state machine (qmeventd-monitor.c).
    Pure logic: events, probe results, I/O samples and the clock are fed in,
    the derived events are recorded.
*/

#include "qmeventd-monitor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char emitted[64][32];
static int n_emitted;
static int failed;

static void rec(void *ctx, const char *event, struct json_object *data) {
    (void)ctx;
    if (n_emitted < 64) {
        snprintf(emitted[n_emitted++], sizeof(emitted[0]), "%s", event);
    }
    json_object_put(data);
}

static void clear(void) { n_emitted = 0; }

static int count(const char *event) {
    int c = 0;
    for (int i = 0; i < n_emitted; i++) {
        c += !strcmp(emitted[i], event);
    }
    return c;
}

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            failed++;                                                                              \
        }                                                                                          \
    } while (0)

#define S(x) ((uint64_t)(x) * 1000ULL)

static void setup(struct VmMon *m, uint64_t now) {
    struct MonHeartbeatConfig hb = {true, 10, 3, 3, 300, 120};
    mon_init(m, now);
    mon_configure(m, now, &hb, true);
    clear();
}

// drive one probe round with the given result
static void probe(struct VmMon *m, uint64_t now, MonProbeResult res) {
    CHECK(mon_probe_due(m, now, false));
    mon_probe_started(m);
    mon_probe_result(m, now, res, rec, NULL);
}

static void test_boot_up(void) {
    struct VmMon m;
    setup(&m, S(1));
    CHECK(!strcmp(mon_heartbeat_str(&m), "booting"));

    // failures before the first answer are not counted
    probe(&m, S(1), PROBE_FAIL);
    probe(&m, S(11), PROBE_FAIL);
    probe(&m, S(21), PROBE_FAIL);
    CHECK(n_emitted == 0);
    CHECK(mon_io_request(&m) == IO_NONE);

    probe(&m, S(31), PROBE_OK);
    CHECK(count("AGENT_UP") == 1);
    CHECK(!strcmp(mon_heartbeat_str(&m), "ok"));
}

static void test_boot_failed(void) {
    struct VmMon m;
    setup(&m, S(1));
    mon_tick(&m, S(200), rec, NULL);
    CHECK(n_emitted == 0);
    mon_tick(&m, S(301), rec, NULL);
    CHECK(count("AGENT_NO_RESPONSE") == 1);
    CHECK(count("BOOT_FAILED") == 1);
    CHECK(!strcmp(mon_heartbeat_str(&m), "no-response"));

    // a late answer brings the agent up
    clear();
    probe(&m, S(311), PROBE_OK);
    CHECK(count("AGENT_UP") == 1);
}

// three failed probes from t: base sample at the first, decision at the third
static void lose_agent(struct VmMon *m, uint64_t t, uint64_t io_first, uint64_t io_last) {
    probe(m, t, PROBE_FAIL);
    CHECK(mon_io_request(m) == IO_WANT_BASE);
    mon_io_sample(m, t, true, io_first, rec, NULL);
    probe(m, t + S(10), PROBE_FAIL);
    CHECK(mon_io_request(m) == IO_NONE);
    probe(m, t + S(20), PROBE_FAIL);
    CHECK(mon_io_request(m) == IO_WANT_DECIDE);
    CHECK(!mon_probe_due(m, t + S(30), false)); // waits for the sample
    mon_io_sample(m, t + S(20), true, io_last, rec, NULL);
}

// one more failed probe with an I/O sample
static void watch(struct VmMon *m, uint64_t t, uint64_t io) {
    probe(m, t, PROBE_FAIL);
    CHECK(mon_io_request(m) == IO_WANT_DECIDE);
    mon_io_sample(m, t, true, io, rec, NULL);
}

static void test_hang(void) {
    struct VmMon m;
    setup(&m, S(1));
    probe(&m, S(1), PROBE_OK);
    clear();

    // agent lost is reported at once, the hang only after hang-timeout (120s)
    lose_agent(&m, S(11), 100, 100);
    CHECK(count("AGENT_LOST") == 1);
    CHECK(count("GUEST_HANG") == 0);
    CHECK(!strcmp(mon_heartbeat_str(&m), "lost"));
    for (uint64_t t = 41; t < 131; t += 10) {
        watch(&m, S(t), 100);
    }
    CHECK(count("GUEST_HANG") == 0); // only 120s - 10s without I/O so far
    watch(&m, S(131), 100);
    CHECK(count("GUEST_HANG") == 1);
    CHECK(count("AGENT_FAULT") == 0);
    CHECK(!strcmp(mon_heartbeat_str(&m), "hang"));

    // decided: further failures do not repeat anything or sample I/O
    clear();
    probe(&m, S(141), PROBE_FAIL);
    CHECK(mon_io_request(&m) == IO_NONE);
    probe(&m, S(151), PROBE_FAIL);
    CHECK(n_emitted == 0);

    probe(&m, S(161), PROBE_OK);
    CHECK(count("AGENT_RECOVERED") == 1);
    CHECK(!strcmp(mon_heartbeat_str(&m), "ok"));
}

static void test_idle_guest_is_no_hang(void) {
    struct VmMon m;
    setup(&m, S(1));
    probe(&m, S(1), PROBE_OK);
    clear();

    // idle guest whose agent died: some I/O within the window -> agent fault
    lose_agent(&m, S(11), 100, 100);
    watch(&m, S(41), 100);
    watch(&m, S(51), 101);
    CHECK(count("AGENT_FAULT") == 1);
    CHECK(count("GUEST_HANG") == 0);
    // decided: no more sampling
    clear();
    probe(&m, S(61), PROBE_FAIL);
    CHECK(mon_io_request(&m) == IO_NONE);
    CHECK(n_emitted == 0);
}

static void test_agent_fault(void) {
    struct VmMon m;
    setup(&m, S(1));
    probe(&m, S(1), PROBE_OK);
    clear();

    lose_agent(&m, S(11), 100, 250);
    CHECK(count("AGENT_LOST") == 1);
    CHECK(count("AGENT_FAULT") == 1);
    CHECK(count("GUEST_HANG") == 0);
    CHECK(!strcmp(mon_heartbeat_str(&m), "lost"));
}

static void test_lost_sample_retried(void) {
    struct VmMon m;
    setup(&m, S(1));
    probe(&m, S(1), PROBE_OK);
    clear();

    // the I/O samples get lost: agent lost anyway, the decision waits
    probe(&m, S(11), PROBE_FAIL);
    mon_io_sample(&m, S(11), false, 0, rec, NULL);
    probe(&m, S(21), PROBE_FAIL);
    probe(&m, S(31), PROBE_FAIL);
    mon_io_sample(&m, S(31), false, 0, rec, NULL);
    CHECK(count("AGENT_LOST") == 1);
    watch(&m, S(41), 500); // first usable sample becomes the base
    watch(&m, S(161), 500);
    CHECK(count("GUEST_HANG") == 1);
}

static void test_busy_and_windows(void) {
    struct VmMon m;
    setup(&m, S(1));
    probe(&m, S(1), PROBE_OK);
    clear();

    // busy probes never count
    for (int i = 0; i < 10; i++) {
        probe(&m, S(11 + 10 * i), PROBE_BUSY);
    }
    CHECK(n_emitted == 0);
    CHECK(mon_io_request(&m) == IO_NONE);

    // no probing during backup, operations, pause
    CHECK(!mon_probe_due(&m, S(500), true));
    mon_on_op_event(&m, S(500), "PRE_SNAPSHOT");
    CHECK(!mon_probe_due(&m, S(500), false));
    CHECK(!strcmp(json_object_get_string(json_object_object_get(mon_state_json(&m), "operation")), "SNAPSHOT"));
    mon_on_op_event(&m, S(510), "POST_SNAPSHOT");
    CHECK(mon_probe_due(&m, S(520), false));

    mon_on_qmp_event(&m, S(520), "STOP", NULL, rec, NULL);
    CHECK(!mon_probe_due(&m, S(600), false));
    CHECK(!strcmp(mon_heartbeat_str(&m), "paused"));
    mon_on_qmp_event(&m, S(600), "RESUME", NULL, rec, NULL);
    CHECK(mon_probe_due(&m, S(610), false));

    // a forgotten operation end expires
    mon_on_op_event(&m, S(1000), "PRE_MIGRATE");
    mon_tick(&m, S(1000) + MON_OP_WINDOW_MAX_MS, rec, NULL);
    CHECK(mon_probe_due(&m, S(1000) + MON_OP_WINDOW_MAX_MS, false));
    CHECK(n_emitted == 0);
}

static void test_crash(void) {
    struct VmMon m;
    setup(&m, S(1));
    probe(&m, S(1), PROBE_OK);
    clear();

    mon_on_qmp_event(&m, S(5), "GUEST_PANICKED", NULL, rec, NULL);
    mon_on_qmp_event(&m, S(6), "GUEST_CRASHLOADED", NULL, rec, NULL);
    CHECK(count("GUEST_CRASH") == 1);
    CHECK(!strcmp(mon_heartbeat_str(&m), "crashed"));
    CHECK(!mon_probe_due(&m, S(100), false));

    // reset starts a new boot, the next crash is reported again
    clear();
    mon_on_qmp_event(&m, S(200), "RESET", NULL, rec, NULL);
    CHECK(!strcmp(mon_heartbeat_str(&m), "booting"));
    mon_on_qmp_event(&m, S(210), "GUEST_PANICKED", NULL, rec, NULL);
    CHECK(count("GUEST_CRASH") == 1);
}

static void test_reboot_loop(void) {
    struct VmMon m;
    setup(&m, S(1));
    for (int i = 0; i < MON_REBOOT_LOOP_COUNT - 1; i++) {
        mon_on_qmp_event(&m, S(10 + i * 60), "RESET", NULL, rec, NULL);
    }
    CHECK(count("REBOOT_LOOP") == 0);
    mon_on_qmp_event(&m, S(400), "RESET", NULL, rec, NULL);
    CHECK(count("REBOOT_LOOP") == 1);
    mon_on_qmp_event(&m, S(410), "RESET", NULL, rec, NULL);
    CHECK(count("REBOOT_LOOP") == 1); // once per window

    // slow resets are no loop
    struct VmMon m2;
    setup(&m2, S(1));
    for (int i = 0; i < 10; i++) {
        mon_on_qmp_event(&m2, S(10 + i * 200), "RESET", NULL, rec, NULL);
    }
    CHECK(count("REBOOT_LOOP") == 0);
}

static void test_storage_fault(void) {
    struct VmMon m;
    setup(&m, S(1));
    mon_on_qmp_event(&m, S(10), "BLOCK_IO_ERROR", NULL, rec, NULL);
    mon_on_qmp_event(&m, S(11), "BLOCK_IO_ERROR", NULL, rec, NULL);
    CHECK(count("STORAGE_FAULT") == 1);
    mon_on_qmp_event(&m, S(100), "BLOCK_IO_ERROR", NULL, rec, NULL);
    CHECK(count("STORAGE_FAULT") == 2);
}

static void test_agent_port_closed(void) {
    struct VmMon m;
    struct json_object *closed = json_tokener_parse("{\"id\":\"qgaport0\",\"open\":false}");
    struct json_object *open = json_tokener_parse("{\"id\":\"qgaport0\",\"open\":true}");
    setup(&m, S(1));
    probe(&m, S(1), PROBE_OK);
    clear();

    mon_on_qmp_event(&m, S(10), "VSERPORT_CHANGE", closed, rec, NULL);
    CHECK(!mon_probe_due(&m, S(20), false));
    mon_tick(&m, S(200), rec, NULL);
    CHECK(n_emitted == 0);

    // the agent restarted (e.g. update): no event
    mon_on_qmp_event(&m, S(250), "VSERPORT_CHANGE", open, rec, NULL);
    CHECK(mon_probe_due(&m, S(250), false));
    mon_tick(&m, S(1000), rec, NULL);
    CHECK(n_emitted == 0);

    // closed for good
    mon_on_qmp_event(&m, S(1000), "VSERPORT_CHANGE", closed, rec, NULL);
    mon_tick(&m, S(1300), rec, NULL);
    CHECK(count("AGENT_LOST") == 1);
    CHECK(count("AGENT_FAULT") == 1);

    json_object_put(closed);
    json_object_put(open);
}

static void test_disabled(void) {
    struct VmMon m;
    mon_init(&m, S(1));
    CHECK(!mon_probe_due(&m, S(100), false));
    mon_tick(&m, S(10000), rec, NULL);
    CHECK(!strcmp(mon_heartbeat_str(&m), "disabled"));

    // crash detection does not need the agent
    clear();
    mon_on_qmp_event(&m, S(20), "GUEST_PANICKED", NULL, rec, NULL);
    CHECK(count("GUEST_CRASH") == 1);
}

static void test_parse_config(void) {
    struct MonHeartbeatConfig hb;
    struct json_object *o = json_tokener_parse(
        "{\"enabled\":1,\"interval\":5,\"timeout\":30,\"failures\":2,\"boot-timeout\":0,"
        "\"hang-timeout\":600}"
    );
    mon_parse_heartbeat_config(o, &hb);
    CHECK(hb.enabled);
    CHECK(hb.interval == 5);
    CHECK(hb.timeout == 4); // clamped below the interval
    CHECK(hb.failures == 2);
    CHECK(hb.boot_timeout == 300); // invalid -> default
    CHECK(hb.hang_timeout == 600);
    json_object_put(o);

    mon_parse_heartbeat_config(NULL, &hb);
    CHECK(!hb.enabled);
}

int main(void) {
    test_boot_up();
    test_boot_failed();
    test_hang();
    test_idle_guest_is_no_hang();
    test_agent_fault();
    test_lost_sample_retried();
    test_busy_and_windows();
    test_crash();
    test_reboot_loop();
    test_storage_fault();
    test_agent_port_closed();
    test_disabled();
    test_parse_config();

    if (failed) {
        fprintf(stderr, "%d check(s) failed\n", failed);
        return 1;
    }
    printf("qmeventd-monitor-test: all tests passed\n");
    return 0;
}
