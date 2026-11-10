// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    qmeventd per-VM monitor state machine.

    Pure logic without any I/O: it is fed with QMP events, injected operation
    events, guest agent probe results, block I/O samples and the clock, and
    reports derived events through a callback. qmeventd.c owns the sockets.

    Events reported through the callback:
      AGENT_UP, AGENT_LOST, AGENT_RECOVERED, AGENT_NO_RESPONSE  (agent monitor)
      GUEST_CRASH, GUEST_HANG, AGENT_FAULT, BOOT_FAILED,
      REBOOT_LOOP, STORAGE_FAULT                                 (composite)
*/

#ifndef QMEVENTD_MONITOR_H
#define QMEVENTD_MONITOR_H

#include <json.h>
#include <stdbool.h>
#include <stdint.h>

#define MON_REBOOT_LOOP_COUNT 5
#define MON_REBOOT_LOOP_WINDOW_MS (600 * 1000ULL)
#define MON_STORAGE_FAULT_INTERVAL_MS (60 * 1000ULL)
#define MON_OP_WINDOW_MAX_MS (3600 * 1000ULL)

typedef enum {
    RUN_RUNNING,
    RUN_PAUSED,
    RUN_SUSPENDED,
    RUN_PANICKED,
    RUN_STOPPING
} MonRunState;

typedef enum {
    AG_DISABLED,
    AG_BOOTING,
    AG_UP,
    AG_LOST,
    AG_NORESP
} MonAgentState;

typedef enum {
    PROBE_OK,
    PROBE_FAIL,
    PROBE_BUSY
} MonProbeResult;

typedef enum {
    IO_NONE,
    IO_WANT_BASE,
    IO_WANT_DECIDE
} MonIoRequest;

struct MonHeartbeatConfig {
    bool enabled;
    unsigned interval;     // seconds between probes
    unsigned timeout;      // seconds a probe may take
    unsigned failures;     // consecutive failures before the agent counts as lost
    unsigned boot_timeout; // seconds after (re)boot to wait for the first response
    unsigned hang_timeout; // seconds without disk I/O after the agent was lost to call it a hang
};

struct VmMon {
    MonRunState run;
    MonAgentState agent;
    struct MonHeartbeatConfig hb;
    bool dispatch; // the VM has a hookscript or vmhook configured

    uint64_t boot_start;
    uint64_t next_probe;
    bool probe_active;
    unsigned fails;
    bool had_up;        // agent answered since the last (re)boot
    bool lost_is_hang;  // decision of the last loss, for the status string

    MonIoRequest io_request;
    bool io_base_valid;
    uint64_t io_base;
    uint64_t io_base_ts;
    bool hang_pending; // agent lost, watching disk I/O to tell hang from agent fault

    int port; // QGA virtio-serial port: -1 unknown, 0 closed, 1 open
    uint64_t port_closed_at;

    char op[32]; // running operation (snapshot, migrate, ...) or empty
    uint64_t op_until;

    uint64_t resets[MON_REBOOT_LOOP_COUNT];
    unsigned reset_idx;
    uint64_t loop_emitted_at;
    bool crash_emitted;
    uint64_t storage_emitted_at;

    char last_event[32];
    uint64_t last_event_ts; // epoch seconds
};

// `data` is owned by the callee (may be NULL)
typedef void (*mon_emit_fn)(void *ctx, const char *event, struct json_object *data);

void mon_init(struct VmMon *m, uint64_t now);
void mon_configure(
    struct VmMon *m, uint64_t now, const struct MonHeartbeatConfig *hb, bool dispatch
);
void mon_set_run_status(struct VmMon *m, uint64_t now, const char *qmp_status);

void mon_on_qmp_event(
    struct VmMon *m,
    uint64_t now,
    const char *event,
    struct json_object *data,
    mon_emit_fn emit,
    void *ctx
);
void mon_on_op_event(struct VmMon *m, uint64_t now, const char *event);

// `backup` is the vzdump guard of qmeventd, it also suspends probing
bool mon_probe_due(struct VmMon *m, uint64_t now, bool backup);
void mon_probe_started(struct VmMon *m);
void mon_probe_result(
    struct VmMon *m, uint64_t now, MonProbeResult res, mon_emit_fn emit, void *ctx
);

MonIoRequest mon_io_request(const struct VmMon *m);
// `valid` false if the sample could not be taken
void mon_io_sample(
    struct VmMon *m, uint64_t now, bool valid, uint64_t total, mon_emit_fn emit, void *ctx
);

// timeouts: boot timeout, closed agent port, stale operation window
void mon_tick(struct VmMon *m, uint64_t now, mon_emit_fn emit, void *ctx);

const char *mon_heartbeat_str(const struct VmMon *m);
struct json_object *mon_state_json(const struct VmMon *m);

bool mon_parse_heartbeat_config(struct json_object *obj, struct MonHeartbeatConfig *out);

#endif /* QMEVENTD_MONITOR_H */
