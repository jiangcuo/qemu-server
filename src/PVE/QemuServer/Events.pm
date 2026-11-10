package PVE::QemuServer::Events;

# Interface to the qmeventd event layer.
#
# qmeventd collects the events of every running VM (QMP events, its own guest
# agent monitoring and events injected from here) and exposes them by journal,
# socket subscription, status query and by running `qm event` for each event.
# This module talks to its socket:
#
#   configure  tell qmeventd the heartbeat settings of a running VM and
#              whether `qm event` has anything to do for it
#   emit       run the hookscript phase of an operation (snapshot, backup,
#              migration, ...) and inject the event into qmeventd
#   query      return the per-VM state qmeventd keeps (heartbeat)

use strict;
use warnings;

use IO::Socket::UNIX;
use IO::Select;
use JSON;

use PVE::GuestHelpers;
use PVE::JSONSchema;

our $SOCKET = '/var/run/qmeventd.sock';

my $heartbeat_fmt = {
    enabled => {
        type => 'boolean',
        default_key => 1,
        description => "Monitor the QEMU guest agent of the VM from its start on.",
    },
    interval => {
        type => 'integer',
        minimum => 2,
        maximum => 3600,
        default => 10,
        optional => 1,
        description => "Seconds between two agent probes.",
    },
    timeout => {
        type => 'integer',
        minimum => 1,
        maximum => 60,
        default => 3,
        optional => 1,
        description => "Seconds an agent probe may take.",
    },
    failures => {
        type => 'integer',
        minimum => 1,
        maximum => 100,
        default => 3,
        optional => 1,
        description => "Consecutive failed probes after which the agent counts as lost.",
    },
    'boot-timeout' => {
        type => 'integer',
        minimum => 10,
        maximum => 86400,
        default => 300,
        optional => 1,
        description => "Seconds after (re)boot the agent has to answer for the first time.",
    },
    'hang-timeout' => {
        type => 'integer',
        minimum => 30,
        maximum => 86400,
        default => 120,
        optional => 1,
        description => "Seconds without any disk I/O after the agent was lost before the guest"
            . " counts as hung. Disk I/O in that time means only the agent failed. An idle"
            . " guest may do no I/O for a while, so do not set this too low.",
    },
};
PVE::JSONSchema::register_format('pve-qm-heartbeat', $heartbeat_fmt);

sub parse_heartbeat {
    my ($value) = @_;

    return { enabled => 0 } if !defined($value);

    my $res = eval { PVE::JSONSchema::parse_property_string($heartbeat_fmt, $value) };
    warn $@ if $@;
    return $res // { enabled => 0 };
}

# QMP and qmeventd event name -> hookscript phase. Events not listed here map
# to their lower case name with '-' (e.g. PRE_SNAPSHOT -> pre-snapshot).
my $phase_map = {
    STARTED => 'started',
    POWERDOWN => 'powerdown',
    STOP => 'pause',
    RESUME => 'resume',
    SUSPEND => 'suspend',
    SUSPEND_DISK => 'suspend-disk',
    WAKEUP => 'wakeup',
    EXITED => 'exited',
    GUEST_PANICKED => 'guest-panic',
    GUEST_CRASHLOADED => 'guest-crashloaded',
    WATCHDOG => 'watchdog',
    BLOCK_IO_ERROR => 'block-io-error',
};

sub event_to_phase {
    my ($event, $data) = @_;

    if ($event eq 'SHUTDOWN') {
        return $data && $data->{guest} ? 'guest-shutdown' : 'host-shutdown';
    }
    if ($event eq 'RESET') {
        return $data && $data->{guest} ? 'guest-reboot' : 'host-reset';
    }
    return $phase_map->{$event} if $phase_map->{$event};

    my $phase = lc($event);
    $phase =~ s/_/-/g;
    return $phase;
}

# send one request line, return the decoded answer line
sub request {
    my ($req, $timeout) = @_;

    $timeout //= 2;

    my $sock = IO::Socket::UNIX->new(Peer => $SOCKET, Type => SOCK_STREAM, Timeout => $timeout)
        or die "unable to connect to qmeventd - $!\n";

    print $sock encode_json($req) . "\n";
    $sock->flush();

    my $sel = IO::Select->new($sock);
    my $buf = '';
    while ($buf !~ m/\n/) {
        die "timeout waiting for qmeventd\n" if !$sel->can_read($timeout);
        my $n = sysread($sock, $buf, 65536, length($buf));
        die "qmeventd closed the connection\n" if !$n;
    }
    close($sock);

    my ($line) = split(/\n/, $buf, 2);
    my $res = decode_json($line);
    die "qmeventd: $res->{error}\n" if defined($res->{error});
    return $res;
}

# Configure qmeventd for a running VM. Called by `qm event STARTED` (so it
# also happens again after a qmeventd restart), on the target of a migration
# and after config changes. With $wait, retry while qmeventd does not know the
# just started QEMU yet.
sub configure {
    my ($vmid, $conf, $agent_enabled, $wait) = @_;

    my $hb = parse_heartbeat($conf->{heartbeat});
    warn "heartbeat of VM $vmid needs the QEMU guest agent ('agent'), not monitoring\n"
        if $hb->{enabled} && !$agent_enabled;

    my $heartbeat = { enabled => ($hb->{enabled} && $agent_enabled) ? JSON::true : JSON::false };
    for my $key (qw(interval timeout failures boot-timeout hang-timeout)) {
        $heartbeat->{$key} = int($hb->{$key}) if defined($hb->{$key});
    }

    my $dispatch = ($conf->{hookscript} || $conf->{vmhook}) ? JSON::true : JSON::false;
    my $req = { configure => { vmid => "$vmid", dispatch => $dispatch, heartbeat => $heartbeat } };

    my $tries = $wait ? 20 : 1;
    while (1) {
        my $res = eval { request($req) };
        return $res if !$@;
        die $@ if --$tries <= 0 || $@ !~ m/VM not running/;
        select(undef, undef, undef, 0.1);
    }
}

sub query_status {
    my ($timeout) = @_;
    return request({ query => 'status' }, $timeout)->{vms} // {};
}

# Report an operation event: run the hookscript phase synchronously in the
# calling task, then inject the event into qmeventd (journal, subscribers,
# monitor windows). Never dies - an event must not break the operation.
sub emit {
    my ($vmid, $event, $data, $conf) = @_;

    my $phase = event_to_phase($event, $data);

    if ($conf && $conf->{hookscript}) {
        eval { PVE::GuestHelpers::exec_hookscript($conf, $vmid, $phase, 0) };
        warn $@ if $@;
    }

    eval {
        request({
            inject => { vmid => "$vmid", event => $event, ($data ? (data => $data) : ()) },
        });
    };
    # qmeventd is not running (e.g. during package upgrades), nothing to report to
    warn "unable to report event $event of VM $vmid - $@" if $@ && $@ !~ m/unable to connect/;

    return;
}

1;
