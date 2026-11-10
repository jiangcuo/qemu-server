#!/usr/bin/perl

# Tests for the VM event helpers: event -> hookscript phase mapping, the
# heartbeat and vmhook option parsing and the destructive action budget.

use strict;
use warnings;

use lib qw(..);

use File::Temp qw(tempdir);
use Test::More;
use Test::MockModule;

use PVE::QemuServer::Events;
use PVE::QemuServer::VMHook;

my $phase = \&PVE::QemuServer::Events::event_to_phase;

# QMP and qmeventd events
is($phase->('STARTED'), 'started', 'STARTED');
is($phase->('SHUTDOWN', { guest => 1 }), 'guest-shutdown', 'guest shutdown');
is($phase->('SHUTDOWN', { guest => 0 }), 'host-shutdown', 'host shutdown');
is($phase->('RESET', { guest => JSON::true }), 'guest-reboot', 'guest reboot');
is($phase->('RESET', {}), 'host-reset', 'host reset');
is($phase->('STOP'), 'pause', 'STOP is pause');
is($phase->('RESUME'), 'resume', 'RESUME');
is($phase->('SUSPEND_DISK'), 'suspend-disk', 'SUSPEND_DISK');
is($phase->('GUEST_PANICKED'), 'guest-panic', 'GUEST_PANICKED');
is($phase->('GUEST_CRASHLOADED'), 'guest-crashloaded', 'GUEST_CRASHLOADED');
is($phase->('BLOCK_IO_ERROR'), 'block-io-error', 'BLOCK_IO_ERROR');
is($phase->('EXITED'), 'exited', 'EXITED');
# monitor and composite events
is($phase->('AGENT_NO_RESPONSE'), 'agent-no-response', 'AGENT_NO_RESPONSE');
is($phase->('GUEST_HANG'), 'guest-hang', 'GUEST_HANG');
is($phase->('REBOOT_LOOP'), 'reboot-loop', 'REBOOT_LOOP');
# operation events
is($phase->('PRE_SNAPSHOT'), 'pre-snapshot', 'PRE_SNAPSHOT');
is($phase->('SNAPSHOT_DELETE_FAILED'), 'snapshot-delete-failed', 'SNAPSHOT_DELETE_FAILED');
is($phase->('MIGRATE_IN'), 'migrate-in', 'MIGRATE_IN');
is($phase->('PRE_RECOVERY'), 'pre-recovery', 'PRE_RECOVERY');

# heartbeat option
is_deeply(PVE::QemuServer::Events::parse_heartbeat(undef), { enabled => 0 }, 'no heartbeat');
my $hb = PVE::QemuServer::Events::parse_heartbeat('1,interval=5,boot-timeout=120');
is($hb->{enabled}, 1, 'heartbeat enabled');
is($hb->{interval}, 5, 'heartbeat interval');
is($hb->{'boot-timeout'}, 120, 'heartbeat boot timeout');

# vmhook option
my $vmhook = PVE::QemuServer::VMHook::parse_vmhook(
    'crash=screenshot+snapshot+reset,hang=notify+reset,max-actions=2,window=600');
is_deeply(
    [PVE::QemuServer::VMHook::actions_for_event($vmhook, 'GUEST_CRASH')],
    [qw(screenshot snapshot reset)],
    'crash rule',
);
is_deeply(
    [PVE::QemuServer::VMHook::actions_for_event($vmhook, 'GUEST_HANG')],
    [qw(notify reset)],
    'hang rule',
);
is_deeply([PVE::QemuServer::VMHook::actions_for_event($vmhook, 'AGENT_FAULT')], [], 'no rule');
is_deeply([PVE::QemuServer::VMHook::actions_for_event(undef, 'GUEST_CRASH')], [], 'no vmhook');

{
    local $SIG{__WARN__} = sub { };
    is(PVE::QemuServer::VMHook::parse_vmhook('crash=reset+reboot'), undef, 'unknown action rejected');
    is(PVE::QemuServer::VMHook::parse_vmhook('crash=reset;stop'), undef, 'bad separator rejected');
}

# destructive action budget
local $PVE::QemuServer::VMHook::STATE_DIR = tempdir(CLEANUP => 1);
my $take = sub { PVE::QemuServer::VMHook::take_action_budget(100, $vmhook, $_[0]) };
ok($take->(1000), 'first action allowed');
ok($take->(1010), 'second action allowed');
ok(!$take->(1020), 'third action in window refused');
ok(!$take->(1590), 'still in window');
ok($take->(1611), 'allowed again after the window');
ok(PVE::QemuServer::VMHook::take_action_budget(101, $vmhook, 1020), 'budget is per VM');

# emit: hookscript phase runs in the task, qmeventd may be missing
my $hook_calls = [];
my $guest_helpers = Test::MockModule->new('PVE::GuestHelpers');
$guest_helpers->mock(exec_hookscript => sub {
    my ($conf, $vmid, $phase, $stop_on_error) = @_;
    push @$hook_calls, [$vmid, $phase, $stop_on_error];
});
local $PVE::QemuServer::Events::SOCKET = '/nonexistent/qmeventd.sock';
{
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    PVE::QemuServer::Events::emit(100, 'PRE_SNAPSHOT', { snapname => 's1' }, { hookscript => 'x' });
    PVE::QemuServer::Events::emit(100, 'POST_SNAPSHOT', undef, {});
    is_deeply($hook_calls, [[100, 'pre-snapshot', 0]], 'hook only with hookscript, never fatal');
    is(scalar(@warnings), 0, 'no warning without qmeventd');
}

# configure: options passed through, agent required, retry for a new VM
{
    my $events = Test::MockModule->new('PVE::QemuServer::Events');
    my @requests;
    my $fail_left = 0;
    $events->mock(request => sub {
        my ($req) = @_;
        push @requests, $req;
        die "qmeventd: VM not running\n" if $fail_left-- > 0;
        return {};
    });

    my $conf = { heartbeat => '1,interval=5,hang-timeout=300', hookscript => 'local:snippets/x' };
    PVE::QemuServer::Events::configure(100, $conf, 1);
    my $c = $requests[-1]->{configure};
    is($c->{vmid}, '100', 'configure vmid');
    ok($c->{dispatch}, 'dispatch with hookscript');
    ok($c->{heartbeat}->{enabled}, 'heartbeat enabled');
    is($c->{heartbeat}->{'hang-timeout'}, 300, 'hang-timeout passed');
    is($c->{heartbeat}->{interval}, 5, 'interval passed');

    my @warnings;
    {
        local $SIG{__WARN__} = sub { push @warnings, @_ };
        PVE::QemuServer::Events::configure(100, { heartbeat => '1' }, 0);
    }
    ok(!$requests[-1]->{configure}->{heartbeat}->{enabled}, 'no heartbeat without agent');
    ok(!$requests[-1]->{configure}->{dispatch}, 'no dispatch without hookscript/vmhook');
    like($warnings[0] // '', qr/needs the QEMU guest agent/, 'warns about missing agent');

    @requests = ();
    $fail_left = 3;
    PVE::QemuServer::Events::configure(100, {}, 1, 1);
    is(scalar(@requests), 4, 'waits for qmeventd to know a just started VM');

    $fail_left = 3;
    eval { PVE::QemuServer::Events::configure(100, {}, 1) };
    like($@, qr/VM not running/, 'no retry without wait');
}

done_testing();
