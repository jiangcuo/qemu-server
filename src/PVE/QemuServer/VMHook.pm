package PVE::QemuServer::VMHook;

# Built-in reactions to VM events (the `vmhook` VM option).
#
# A rule maps an event to an ordered chain of actions, e.g.
#   vmhook: crash=screenshot+snapshot+notify+reset,hang=screenshot+notify+reset
# Rules are evaluated by `qm event` after the hookscript phase of the event
# ran. Destructive actions (snapshot, pause, reset, stop) are limited to
# `max-actions` per `window` seconds, so a crashing guest cannot loop forever.

use strict;
use warnings;

use File::Path qw(make_path);
use JSON;
use POSIX qw(strftime);

use PVE::GuestHelpers;
use PVE::JSONSchema;
use PVE::INotify;
use PVE::Tools;

our $SCREENSHOT_DIR = '/var/lib/qemu-server/screenshots';
our $STATE_DIR = '/var/run/qemu-server';
my $SCREENSHOTS_KEEP = 10;

my $ACTION_RE = qr/log|screenshot|snapshot|notify|pause|reset|stop/;
my $destructive = { snapshot => 1, pause => 1, reset => 1, stop => 1 };

PVE::JSONSchema::register_format(
    'pve-qm-vmhook-actions',
    sub {
        my ($value, $noerr) = @_;
        return $value if $value =~ m/^(?:$ACTION_RE)(?:\+(?:$ACTION_RE))*$/;
        return undef if $noerr;
        die "invalid action list '$value'\n";
    },
);

my $actions_prop = sub {
    my ($desc) = @_;
    return {
        type => 'string',
        format => 'pve-qm-vmhook-actions',
        typetext => '<action>[+<action>...]',
        optional => 1,
        description => "Actions on $desc, any of log, screenshot, snapshot, notify, pause,"
            . " reset, stop, joined by '+'.",
    };
};

# rule key => events that trigger it
my $rule_events = {
    crash => ['GUEST_CRASH'],
    hang => ['GUEST_HANG'],
    'agent-fault' => ['AGENT_FAULT'],
    'boot-failed' => ['BOOT_FAILED'],
    'reboot-loop' => ['REBOOT_LOOP'],
    'storage-fault' => ['STORAGE_FAULT'],
    watchdog => ['WATCHDOG'],
};

my $vmhook_fmt = {
    crash => $actions_prop->('a guest crash (pvpanic / Hyper-V crash notification, machine 10.0+pve2)'),
    hang => $actions_prop->('a hung guest (agent lost and no disk I/O)'),
    'agent-fault' => $actions_prop->('a lost guest agent while the guest still does I/O'),
    'boot-failed' => $actions_prop->('no agent answer within the boot timeout'),
    'reboot-loop' => $actions_prop->('repeated guest resets in a short time'),
    'storage-fault' => $actions_prop->('a disk I/O error'),
    watchdog => $actions_prop->('a fired watchdog device'),
    'max-actions' => {
        type => 'integer',
        minimum => 1,
        maximum => 100,
        default => 3,
        optional => 1,
        description => "Maximum number of destructive actions (snapshot, pause, reset, stop)"
            . " per window. Further events only run log, screenshot and notify.",
    },
    window => {
        type => 'integer',
        minimum => 60,
        maximum => 604800,
        default => 3600,
        optional => 1,
        description => "Window in seconds for 'max-actions'.",
    },
    delay => {
        type => 'integer',
        minimum => 0,
        maximum => 300,
        default => 5,
        optional => 1,
        description => "Seconds to wait before running the actions, e.g. to let the guest"
            . " draw its crash screen.",
    },
};
PVE::JSONSchema::register_format('pve-qm-vmhook', $vmhook_fmt);

sub parse_vmhook {
    my ($value) = @_;

    return undef if !defined($value);
    my $res = eval { PVE::JSONSchema::parse_property_string($vmhook_fmt, $value) };
    warn $@ if $@;
    return $res;
}

# actions configured for an event, empty list if none
sub actions_for_event {
    my ($vmhook, $event) = @_;

    return () if !$vmhook;
    for my $rule (sort keys %$rule_events) {
        next if !grep { $_ eq $event } $rule_events->{$rule}->@*;
        my $chain = $vmhook->{$rule} // next;
        return split(/\+/, $chain);
    }
    return ();
}

my sub state_file {
    my ($vmid) = @_;
    return "$STATE_DIR/$vmid.vmhook";
}

my sub load_state {
    my ($vmid) = @_;
    my $file = state_file($vmid);
    my $raw = -f $file ? PVE::Tools::file_get_contents($file) : undef;
    my $state = $raw ? eval { decode_json($raw) } : undef;
    return $state // { actions => [] };
}

# true if another destructive action is allowed, records it if so
sub take_action_budget {
    my ($vmid, $vmhook, $now) = @_;

    my $max = $vmhook->{'max-actions'} // 3;
    my $window = $vmhook->{window} // 3600;

    my $state = load_state($vmid);
    my $recent = [grep { $_ > $now - $window } ($state->{actions} // [])->@*];
    return 0 if scalar(@$recent) >= $max;

    push @$recent, $now;
    $state->{actions} = $recent;
    PVE::Tools::file_set_contents(state_file($vmid), encode_json($state));
    return 1;
}

# forget everything about a removed VM, so a reused VMID starts clean
sub purge {
    my ($vmid) = @_;
    unlink state_file($vmid);
    File::Path::remove_tree("$SCREENSHOT_DIR/$vmid") if -d "$SCREENSHOT_DIR/$vmid";
}

sub screenshot {
    my ($vmid, $event) = @_;

    my $dir = "$SCREENSHOT_DIR/$vmid";
    make_path($dir, { mode => 0700 });

    my $name = lc($event) . '-' . strftime('%Y%m%d-%H%M%S', gmtime()) . "-$$.png";
    my $tmp = "$dir/.$name.tmp";

    eval {
        PVE::QemuServer::Monitor::mon_cmd($vmid, 'screendump', filename => $tmp, format => 'png');
        die "no image written\n" if !-s $tmp;
        chmod(0600, $tmp);
        rename($tmp, "$dir/$name") or die "rename failed - $!\n";
    };
    if (my $err = $@) {
        unlink $tmp;
        die $err;
    }

    # keep only the newest screenshots
    opendir(my $dh, $dir) or return "$dir/$name";
    my @pngs = sort grep { m/\.png$/ } readdir($dh);
    closedir($dh);
    my @by_age = sort { (stat("$dir/$a"))[9] <=> (stat("$dir/$b"))[9] } @pngs;
    while (scalar(@by_age) > $SCREENSHOTS_KEEP) {
        unlink "$dir/" . shift(@by_age);
    }

    return "$dir/$name";
}

sub notify {
    my ($vmid, $conf, $event, $ev, $screenshot) = @_;

    require PVE::Notify;

    my $data = PVE::Notify::common_template_data();
    $data->{vmid} = $vmid;
    $data->{name} = $conf->{name} // "VM $vmid";
    $data->{event} = $event;
    $data->{details} = encode_json($ev->{data} // {});
    $data->{screenshot} = $screenshot if $screenshot;

    my $fields = {
        type => 'vm-event',
        hostname => PVE::INotify::nodename(),
        'vm-event' => $event,
    };
    my $severity = $event =~ m/^(?:GUEST_CRASH|GUEST_HANG|BOOT_FAILED|REBOOT_LOOP|STORAGE_FAULT)$/
        ? 'error'
        : 'warning';

    PVE::Notify::notify($severity, 'vm-event', $data, $fields);
}

sub run_destructive {
    my ($vmid, $action, $event) = @_;

    if ($action eq 'snapshot') {
        my $snapname = 'auto-' . lc($event =~ s/_/-/gr) . '-' . strftime('%Y%m%d%H%M%S', localtime());
        PVE::QemuConfig->snapshot_create(
            $vmid, $snapname, 0, "automatic snapshot on $event (vmhook)",
        );
        return $snapname;
    } elsif ($action eq 'pause') {
        PVE::QemuServer::vm_suspend($vmid, 0);
    } elsif ($action eq 'reset') {
        PVE::QemuServer::vm_reset($vmid, 0);
    } elsif ($action eq 'stop') {
        my $storecfg = PVE::Storage::config();
        PVE::QemuServer::vm_stop($storecfg, $vmid, 0, 0, 10, 0, 1);
    }
    return undef;
}

# Run the vmhook rule for one event. `$ev` is the decoded qmeventd event.
sub handle_event {
    my ($vmid, $conf, $event, $ev) = @_;

    my $vmhook = parse_vmhook($conf->{vmhook}) // return;
    my @actions = actions_for_event($vmhook, $event);
    return if !@actions;

    print "vmhook: VM $vmid $event -> " . join('+', @actions) . "\n";

    my $delay = $vmhook->{delay} // 5;
    sleep($delay) if $delay;

    my $screenshot;
    my $budget_checked;
    my $budget_ok;
    my $recovery_started;

    for my $action (@actions) {
        eval {
            if ($action eq 'log') {
                print "vmhook: VM $vmid event $event: " . encode_json($ev->{data} // {}) . "\n";
            } elsif ($action eq 'screenshot') {
                $screenshot = screenshot($vmid, $event);
                print "vmhook: VM $vmid screenshot saved to $screenshot\n";
            } elsif ($action eq 'notify') {
                notify($vmid, $conf, $event, $ev, $screenshot);
            } elsif ($destructive->{$action}) {
                if (!$budget_checked) {
                    $budget_ok = take_action_budget($vmid, $vmhook, time());
                    $budget_checked = 1;
                    print "vmhook: VM $vmid reached max-actions, skipping destructive actions\n"
                        if !$budget_ok;
                }
                return if !$budget_ok;

                # the action must hit the QEMU process that raised the event
                my $pid = PVE::QemuServer::check_running($vmid);
                die "VM is no longer running\n" if !$pid;
                die "VM was restarted since the event\n" if $ev->{pid} && $pid != $ev->{pid};

                if (!$recovery_started) {
                    $recovery_started = 1;
                    PVE::QemuServer::Events::emit(
                        $vmid, 'PRE_RECOVERY', { event => $event, actions => \@actions }, $conf,
                    );
                }
                my $res = run_destructive($vmid, $action, $event);
                print "vmhook: VM $vmid $action done" . ($res ? " ($res)" : '') . "\n";
            }
        };
        warn "vmhook: VM $vmid action '$action' on $event failed - $@" if $@;
    }

    if ($recovery_started) {
        PVE::QemuServer::Events::emit(
            $vmid, 'POST_RECOVERY', { event => $event, actions => \@actions }, $conf,
        );
    }
}

1;
