// SPDX-License-Identifier: AGPL-3.0-or-later
/*
    qmeventd per-VM monitor state machine, see qmeventd-monitor.h

    All times are monotonic milliseconds.

    Agent monitoring starts with the QEMU process: the agent is BOOTING until
    the first answer (AGENT_UP). Without an answer within boot-timeout it is
    reported as AGENT_NO_RESPONSE (plus BOOT_FAILED if it never answered since
    the last boot). Once up, `failures` consecutive failed probes make it LOST;
    AGENT_LOST is reported at once. Whether it is a GUEST_HANG or only an
    AGENT_FAULT is decided by the block I/O counters, starting at the first
    failed probe: any I/O means the guest still works (AGENT_FAULT at once),
    no I/O at all for hang-timeout seconds means a hang. An idle guest can be
    without disk I/O for a while, so the window must not be too short.
*/

#include "qmeventd-monitor.h"

#include <stdio.h>
#include <string.h>

#define SEC(x) ((uint64_t)(x) * 1000ULL)

static void emit_simple(mon_emit_fn emit, void *ctx, const char *event) {
    if (emit) {
        emit(ctx, event, NULL);
    }
}

static void reset_failures(struct VmMon *m) {
    m->fails = 0;
    m->io_request = IO_NONE;
    m->io_base_valid = false;
    m->hang_pending = false;
}

static void restart_boot(struct VmMon *m, uint64_t now) {
    reset_failures(m);
    m->boot_start = now;
    m->next_probe = now;
    m->had_up = false;
    m->lost_is_hang = false;
    m->agent = m->hb.enabled ? AG_BOOTING : AG_DISABLED;
}

void mon_init(struct VmMon *m, uint64_t now) {
    memset(m, 0, sizeof(*m));
    m->run = RUN_RUNNING;
    m->agent = AG_DISABLED;
    m->port = -1;
    m->hb.interval = 10;
    m->hb.timeout = 3;
    m->hb.failures = 3;
    m->hb.boot_timeout = 300;
    m->hb.hang_timeout = 120;
    m->boot_start = now;
}

void mon_configure(
    struct VmMon *m, uint64_t now, const struct MonHeartbeatConfig *hb, bool dispatch
) {
    bool was_enabled = m->hb.enabled;

    m->dispatch = dispatch;
    m->hb = *hb;
    if (m->hb.interval == 0) {
        m->hb.interval = 10;
    }
    if (m->hb.timeout == 0) {
        m->hb.timeout = 3;
    }
    if (m->hb.failures == 0) {
        m->hb.failures = 3;
    }
    if (m->hb.boot_timeout == 0) {
        m->hb.boot_timeout = 300;
    }
    if (m->hb.hang_timeout == 0) {
        m->hb.hang_timeout = 120;
    }

    if (!m->hb.enabled) {
        m->agent = AG_DISABLED;
        reset_failures(m);
    } else if (!was_enabled) {
        // enabled on a running VM: give the agent a full boot window. The
        // boot start is kept, so a configure right after start does not
        // extend the window
        reset_failures(m);
        m->agent = AG_BOOTING;
        m->had_up = false;
        if (now - m->boot_start > SEC(m->hb.boot_timeout)) {
            m->boot_start = now;
        }
        m->next_probe = now;
    }
}

void mon_set_run_status(struct VmMon *m, uint64_t now, const char *status) {
    (void)now;
    if (!status || m->run == RUN_PANICKED || m->run == RUN_STOPPING) {
        return;
    }
    if (!strcmp(status, "running")) {
        m->run = RUN_RUNNING;
    } else if (!strcmp(status, "suspended")) {
        m->run = RUN_SUSPENDED;
    } else if (!strcmp(status, "guest-panicked")) {
        m->run = RUN_PANICKED;
    } else if (!strcmp(status, "shutdown")) {
        m->run = RUN_STOPPING;
    } else {
        // paused, prelaunch, inmigrate, postmigrate, finish-migrate, ...
        m->run = RUN_PAUSED;
    }
}

static void become_running(struct VmMon *m, uint64_t now) {
    m->run = RUN_RUNNING;
    // time spent paused does not count against the agent
    reset_failures(m);
    if (m->agent == AG_BOOTING) {
        m->boot_start = now;
    }
    m->next_probe = now + SEC(m->hb.interval);
}

static void record_reset(struct VmMon *m, uint64_t now, mon_emit_fn emit, void *ctx) {
    m->resets[m->reset_idx] = now;
    m->reset_idx = (m->reset_idx + 1) % MON_REBOOT_LOOP_COUNT;

    // the slot we will overwrite next is the oldest of the last N resets
    uint64_t oldest = m->resets[m->reset_idx];
    if (oldest == 0 || now - oldest > MON_REBOOT_LOOP_WINDOW_MS) {
        return;
    }
    if (m->loop_emitted_at && now - m->loop_emitted_at <= MON_REBOOT_LOOP_WINDOW_MS) {
        return;
    }
    m->loop_emitted_at = now;
    if (emit) {
        struct json_object *d = json_object_new_object();
        json_object_object_add(d, "count", json_object_new_int(MON_REBOOT_LOOP_COUNT));
        json_object_object_add(
            d, "window", json_object_new_int((int)(MON_REBOOT_LOOP_WINDOW_MS / 1000))
        );
        emit(ctx, "REBOOT_LOOP", d);
    }
}

void mon_on_qmp_event(
    struct VmMon *m,
    uint64_t now,
    const char *event,
    struct json_object *data,
    mon_emit_fn emit,
    void *ctx
) {
    if (!event) {
        return;
    }

    if (!strcmp(event, "GUEST_PANICKED") || !strcmp(event, "GUEST_CRASHLOADED")) {
        m->run = RUN_PANICKED;
        m->io_request = IO_NONE;
        // PANICKED and CRASHLOADED of the same incident are one crash
        if (!m->crash_emitted) {
            m->crash_emitted = true;
            if (emit) {
                struct json_object *d = json_object_new_object();
                json_object_object_add(d, "trigger", json_object_new_string(event));
                if (data) {
                    json_object_object_add(d, "qmp", json_object_get(data));
                }
                emit(ctx, "GUEST_CRASH", d);
            }
        }
    } else if (!strcmp(event, "RESET")) {
        m->run = RUN_RUNNING;
        m->crash_emitted = false;
        restart_boot(m, now);
        record_reset(m, now, emit, ctx);
    } else if (!strcmp(event, "STOP")) {
        if (m->run == RUN_RUNNING) {
            m->run = RUN_PAUSED;
        }
    } else if (!strcmp(event, "RESUME") || !strcmp(event, "WAKEUP")) {
        if (m->run == RUN_PAUSED || m->run == RUN_SUSPENDED) {
            become_running(m, now);
        }
    } else if (!strcmp(event, "SUSPEND")) {
        m->run = RUN_SUSPENDED;
    } else if (!strcmp(event, "SHUTDOWN") || !strcmp(event, "SUSPEND_DISK")) {
        m->run = RUN_STOPPING;
    } else if (!strcmp(event, "BLOCK_IO_ERROR")) {
        if (!m->storage_emitted_at || now - m->storage_emitted_at > MON_STORAGE_FAULT_INTERVAL_MS) {
            m->storage_emitted_at = now;
            if (emit) {
                emit(ctx, "STORAGE_FAULT", data ? json_object_get(data) : NULL);
            }
        }
    } else if (!strcmp(event, "VSERPORT_CHANGE")) {
        struct json_object *id, *open;
        if (data && json_object_object_get_ex(data, "id", &id) &&
            !strcmp(json_object_get_string(id), "qgaport0") &&
            json_object_object_get_ex(data, "open", &open)) {
            if (json_object_get_boolean(open)) {
                m->port = 1;
                m->next_probe = now;
            } else {
                m->port = 0;
                m->port_closed_at = now;
                reset_failures(m);
            }
        }
    }
}

static const char *const op_events[][3] = {
    // begin, end, failed
    {"PRE_SNAPSHOT", "POST_SNAPSHOT", "SNAPSHOT_FAILED"},
    {"PRE_SNAPSHOT_DELETE", "POST_SNAPSHOT_DELETE", "SNAPSHOT_DELETE_FAILED"},
    {"PRE_ROLLBACK", "POST_ROLLBACK", "ROLLBACK_FAILED"},
    {"PRE_BACKUP", "POST_BACKUP", "BACKUP_FAILED"},
    {"PRE_MIGRATE", "POST_MIGRATE", "MIGRATE_FAILED"},
};

void mon_on_op_event(struct VmMon *m, uint64_t now, const char *event) {
    for (size_t i = 0; i < sizeof(op_events) / sizeof(op_events[0]); i++) {
        if (!strcmp(event, op_events[i][0])) {
            snprintf(m->op, sizeof(m->op), "%s", event + 4);
            m->op_until = now + MON_OP_WINDOW_MAX_MS;
            reset_failures(m);
            return;
        }
        if (!strcmp(event, op_events[i][1]) || !strcmp(event, op_events[i][2])) {
            m->op[0] = '\0';
            m->op_until = 0;
            reset_failures(m);
            m->next_probe = now + SEC(m->hb.interval);
            return;
        }
    }
}

bool mon_probe_due(struct VmMon *m, uint64_t now, bool backup) {
    if (!m->hb.enabled || m->probe_active || m->io_request != IO_NONE) {
        return false;
    }
    // a closed agent port cannot answer, mon_tick handles it
    if (m->run != RUN_RUNNING || backup || m->op[0] || m->port == 0) {
        return false;
    }
    return now >= m->next_probe;
}

void mon_probe_started(struct VmMon *m) { m->probe_active = true; }

void mon_probe_result(
    struct VmMon *m, uint64_t now, MonProbeResult res, mon_emit_fn emit, void *ctx
) {
    m->probe_active = false;
    m->next_probe = now + SEC(m->hb.interval);

    // the VM changed state while the probe was running, ignore the result
    if (!m->hb.enabled || m->run != RUN_RUNNING) {
        return;
    }

    switch (res) {
    case PROBE_BUSY:
        break;

    case PROBE_OK: {
        MonAgentState old = m->agent;
        reset_failures(m);
        m->agent = AG_UP;
        m->had_up = true;
        if (old == AG_LOST) {
            emit_simple(emit, ctx, "AGENT_RECOVERED");
        } else if (old == AG_BOOTING || old == AG_NORESP) {
            emit_simple(emit, ctx, "AGENT_UP");
        }
        break;
    }

    case PROBE_FAIL:
        if (m->agent == AG_LOST && m->hang_pending) {
            m->io_request = IO_WANT_DECIDE; // keep watching the disk I/O
            break;
        }
        // before the first answer only the boot timeout counts
        if (m->agent != AG_UP) {
            break;
        }
        m->fails++;
        if (m->fails == 1) {
            m->io_request = IO_WANT_BASE;
        } else if (m->fails >= m->hb.failures) {
            m->io_request = IO_WANT_DECIDE;
        }
        break;
    }
}

MonIoRequest mon_io_request(const struct VmMon *m) { return m->io_request; }

static struct json_object *loss_data(struct VmMon *m) {
    struct json_object *d = json_object_new_object();
    json_object_object_add(d, "failures", json_object_new_int((int)m->fails));
    return d;
}

void mon_io_sample(
    struct VmMon *m, uint64_t now, bool valid, uint64_t total, mon_emit_fn emit, void *ctx
) {
    MonIoRequest req = m->io_request;
    m->io_request = IO_NONE;

    if (req == IO_NONE || m->run != RUN_RUNNING) {
        return;
    }

    // the first sample is the base of the hang window
    if (valid && !m->io_base_valid) {
        m->io_base_valid = true;
        m->io_base = total;
        m->io_base_ts = now;
    }
    if (req == IO_WANT_BASE && m->fails < m->hb.failures) {
        return;
    }

    // enough failed probes: the agent is lost, report that right away
    if (m->agent == AG_UP) {
        m->agent = AG_LOST;
        m->lost_is_hang = false;
        m->hang_pending = true;
        if (emit) {
            emit(ctx, "AGENT_LOST", loss_data(m));
        }
    }
    if (!m->hang_pending || !valid || !m->io_base_valid) {
        return; // no usable sample yet, try again with the next probe
    }

    if (total != m->io_base) {
        // the guest still does I/O: only the agent is broken
        m->hang_pending = false;
        if (emit) {
            struct json_object *d = loss_data(m);
            json_object_object_add(d, "io_active", json_object_new_boolean(true));
            emit(ctx, "AGENT_FAULT", d);
        }
    } else if (now - m->io_base_ts >= SEC(m->hb.hang_timeout)) {
        m->hang_pending = false;
        m->lost_is_hang = true;
        if (emit) {
            struct json_object *d = loss_data(m);
            json_object_object_add(d, "io_active", json_object_new_boolean(false));
            json_object_object_add(
                d, "idle_seconds", json_object_new_int64((int64_t)((now - m->io_base_ts) / 1000))
            );
            emit(ctx, "GUEST_HANG", d);
        }
    }
}

void mon_tick(struct VmMon *m, uint64_t now, mon_emit_fn emit, void *ctx) {
    if (m->op[0] && now >= m->op_until) {
        // the end of the operation was never reported, do not block forever
        m->op[0] = '\0';
        m->op_until = 0;
    }

    if (!m->hb.enabled || m->run != RUN_RUNNING) {
        return;
    }

    if (m->agent == AG_BOOTING && now - m->boot_start >= SEC(m->hb.boot_timeout)) {
        m->agent = AG_NORESP;
        emit_simple(emit, ctx, "AGENT_NO_RESPONSE");
        if (!m->had_up) {
            emit_simple(emit, ctx, "BOOT_FAILED");
        }
        return;
    }

    // the agent closed its port inside a running guest and did not come back
    if (m->agent == AG_UP && m->port == 0 && now - m->port_closed_at >= SEC(m->hb.boot_timeout)) {
        m->agent = AG_LOST;
        m->lost_is_hang = false;
        if (emit) {
            struct json_object *d = json_object_new_object();
            json_object_object_add(d, "reason", json_object_new_string("agent port closed"));
            emit(ctx, "AGENT_LOST", json_object_get(d));
            emit(ctx, "AGENT_FAULT", d);
        }
    }
}

const char *mon_heartbeat_str(const struct VmMon *m) {
    switch (m->run) {
    case RUN_PANICKED:
        return "crashed";
    case RUN_PAUSED:
    case RUN_SUSPENDED:
        return "paused";
    case RUN_STOPPING:
        return "stopping";
    case RUN_RUNNING:
        break;
    }
    switch (m->agent) {
    case AG_DISABLED:
        return "disabled";
    case AG_BOOTING:
        return "booting";
    case AG_UP:
        return "ok";
    case AG_NORESP:
        return "no-response";
    case AG_LOST:
        return m->lost_is_hang ? "hang" : "lost";
    }
    return "unknown";
}

static const char *run_str(MonRunState s) {
    switch (s) {
    case RUN_RUNNING:
        return "running";
    case RUN_PAUSED:
        return "paused";
    case RUN_SUSPENDED:
        return "suspended";
    case RUN_PANICKED:
        return "panicked";
    case RUN_STOPPING:
        return "stopping";
    }
    return "unknown";
}

static const char *agent_str(MonAgentState s) {
    switch (s) {
    case AG_DISABLED:
        return "disabled";
    case AG_BOOTING:
        return "booting";
    case AG_UP:
        return "up";
    case AG_LOST:
        return "lost";
    case AG_NORESP:
        return "no-response";
    }
    return "unknown";
}

struct json_object *mon_state_json(const struct VmMon *m) {
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "heartbeat", json_object_new_string(mon_heartbeat_str(m)));
    json_object_object_add(o, "run", json_object_new_string(run_str(m->run)));
    json_object_object_add(o, "agent", json_object_new_string(agent_str(m->agent)));
    if (m->port >= 0) {
        json_object_object_add(o, "agent_port", json_object_new_boolean(m->port));
    }
    if (m->op[0]) {
        json_object_object_add(o, "operation", json_object_new_string(m->op));
    }
    if (m->last_event[0]) {
        json_object_object_add(o, "last_event", json_object_new_string(m->last_event));
        json_object_object_add(o, "last_event_time", json_object_new_int64((int64_t)m->last_event_ts));
    }
    return o;
}

static unsigned get_uint(struct json_object *obj, const char *key, unsigned def, unsigned max) {
    struct json_object *v;
    if (!json_object_object_get_ex(obj, key, &v)) {
        return def;
    }
    int64_t i = json_object_get_int64(v);
    if (i <= 0 || (uint64_t)i > max) {
        return def;
    }
    return (unsigned)i;
}

bool mon_parse_heartbeat_config(struct json_object *obj, struct MonHeartbeatConfig *out) {
    struct json_object *v;
    memset(out, 0, sizeof(*out));
    if (!obj || !json_object_is_type(obj, json_type_object)) {
        return true; // no heartbeat section: disabled
    }
    out->enabled = json_object_object_get_ex(obj, "enabled", &v) && json_object_get_boolean(v);
    out->interval = get_uint(obj, "interval", 10, 3600);
    out->timeout = get_uint(obj, "timeout", 3, 60);
    out->failures = get_uint(obj, "failures", 3, 100);
    out->boot_timeout = get_uint(obj, "boot-timeout", 300, 86400);
    out->hang_timeout = get_uint(obj, "hang-timeout", 120, 86400);
    if (out->timeout >= out->interval) {
        out->timeout = out->interval > 1 ? out->interval - 1 : 1;
    }
    return true;
}
