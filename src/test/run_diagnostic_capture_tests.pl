#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

use Test::More;
use JSON::PP;
use File::Temp qw(tempdir);
use File::Basename qw(basename);
use File::stat;

use PVE::QemuServer::DiagnosticCapture;

# ---------------------------------------------------------------------------
# parse_capture_string
# ---------------------------------------------------------------------------

is_deeply(
    PVE::QemuServer::DiagnosticCapture::parse_capture_string(undef),
    { panic => 0, heartbeat => 0 },
    'parse undef capture string => both off',
);

is_deeply(
    PVE::QemuServer::DiagnosticCapture::parse_capture_string(''),
    { panic => 0, heartbeat => 0 },
    'parse empty capture string => both off',
);

is_deeply(
    PVE::QemuServer::DiagnosticCapture::parse_capture_string('panic=1,heartbeat=1'),
    { panic => 1, heartbeat => 1 },
    'parse panic=1,heartbeat=1',
);

is_deeply(
    PVE::QemuServer::DiagnosticCapture::parse_capture_string('panic=0,heartbeat=0'),
    { panic => 0, heartbeat => 0 },
    'parse panic=0,heartbeat=0',
);

is_deeply(
    PVE::QemuServer::DiagnosticCapture::parse_capture_string('heartbeat=1'),
    { panic => 0, heartbeat => 1 },
    'parse partial string keeps missing flag off',
);

is_deeply(
    PVE::QemuServer::DiagnosticCapture::parse_capture_string('panic=on,heartbeat=yes'),
    { panic => 1, heartbeat => 1 },
    'parse boolean aliases',
);

is_deeply(
    PVE::QemuServer::DiagnosticCapture::parse_capture_string('panic=off,heartbeat=no'),
    { panic => 0, heartbeat => 0 },
    'parse boolean off aliases',
);

is_deeply(
    PVE::QemuServer::DiagnosticCapture::parse_capture_string('foo=1,panic=1'),
    { panic => 1, heartbeat => 0 },
    'parse ignores unknown keys',
);

# ---------------------------------------------------------------------------
# normalize_policy
# ---------------------------------------------------------------------------

my $np = PVE::QemuServer::DiagnosticCapture::normalize_policy(
    111,
    capture => { panic => 1, heartbeat => 1 },
    agent => 1,
);

is($np->{version}, 1, 'policy version is 1');
is($np->{vmid}, 111, 'policy vmid preserved');
is($np->{panic}, JSON::PP::true, 'panic enabled');
is($np->{heartbeat}, JSON::PP::true, 'heartbeat enabled with agent');
is($np->{agent}, JSON::PP::true, 'agent flag enabled');
is($np->{maintenance}, JSON::PP::false, 'maintenance defaults to false');
is($np->{heartbeat_interval}, 10, 'heartbeat_interval default');
is($np->{heartbeat_timeout}, 3, 'heartbeat_timeout default');
is($np->{failure_threshold}, 3, 'failure_threshold default');
is($np->{recovery_threshold}, 2, 'recovery_threshold default');
is($np->{grace_period}, 60, 'grace_period default');
is($np->{screenshot_timeout}, 5, 'screenshot_timeout default');

is_deeply(
    [sort keys %$np],
    [
        sort qw(version vmid panic heartbeat agent maintenance heartbeat_interval
            heartbeat_timeout failure_threshold recovery_threshold grace_period
            screenshot_timeout)
    ],
    'policy contains exactly the contracted keys',
);

my $np_noagent = PVE::QemuServer::DiagnosticCapture::normalize_policy(
    111,
    capture => { panic => 1, heartbeat => 1 },
    agent => 0,
);

is($np_noagent->{panic}, JSON::PP::true, 'panic capture does not depend on agent');
is($np_noagent->{heartbeat}, JSON::PP::false, 'effective heartbeat off without agent');
is($np_noagent->{agent}, JSON::PP::false, 'agent flag reflects effective config');

my $np_off = PVE::QemuServer::DiagnosticCapture::normalize_policy(123, capture => undef);
is($np_off->{panic}, JSON::PP::false, 'missing capture => panic off');
is($np_off->{heartbeat}, JSON::PP::false, 'missing capture => heartbeat off');
is($np_off->{agent}, JSON::PP::false, 'missing agent => off');

my $np_str = PVE::QemuServer::DiagnosticCapture::normalize_policy(
    7,
    capture => 'panic=1,heartbeat=1',
    agent => 1,
);
is($np_str->{panic}, JSON::PP::true, 'normalize accepts raw capture string');

my $np_maint = PVE::QemuServer::DiagnosticCapture::normalize_policy(
    7,
    capture => { panic => 1, heartbeat => 1 },
    agent => 1,
    maintenance => 1,
);
is($np_maint->{maintenance}, JSON::PP::true, 'maintenance flag honoured');

eval { PVE::QemuServer::DiagnosticCapture::normalize_policy('abc', capture => undef) };
like($@, qr/vmid/i, 'normalize rejects non-numeric vmid');

# ---------------------------------------------------------------------------
# policy_path / publish_policy / remove_policy
# ---------------------------------------------------------------------------

my $tmp = tempdir(CLEANUP => 1);
my $root = "$tmp/run-qemu-server";

is(
    PVE::QemuServer::DiagnosticCapture::policy_path(111, $root),
    "$root/111.capture-policy.json",
    'policy path uses <vmid>.capture-policy.json',
);

my $policy = PVE::QemuServer::DiagnosticCapture::normalize_policy(
    111,
    capture => { panic => 1, heartbeat => 1 },
    agent => 1,
);

PVE::QemuServer::DiagnosticCapture::publish_policy(111, $policy, $root);

my $path = "$root/111.capture-policy.json";
ok(-f $path, 'publish_policy creates the policy file (and its dir)');

my $st = stat($path);
is($st->mode & 07777, 0600, 'policy file mode is 0600');

my $raw = do { local $/; open my $fh, '<', $path or die $!; <$fh> };
my $decoded = JSON::PP->new->decode($raw);
is($decoded->{vmid}, 111, 'published JSON round-trips vmid');
is($decoded->{panic}, JSON::PP::true, 'published JSON panic');
is($decoded->{heartbeat}, JSON::PP::true, 'published JSON heartbeat');

my @leftover = grep { basename($_) =~ /\.tmp/ } glob("$root/*");
is_deeply(\@leftover, [], 'no temp files left after publish');

# overwriting (VMID reuse) replaces content atomically
my $policy2 = PVE::QemuServer::DiagnosticCapture::normalize_policy(
    111,
    capture => { panic => 0, heartbeat => 0 },
    agent => 0,
);
PVE::QemuServer::DiagnosticCapture::publish_policy(111, $policy2, $root);
my $raw2 = do { local $/; open my $fh2, '<', $path or die $!; <$fh2> };
my $decoded2 = JSON::PP->new->decode($raw2);
is($decoded2->{panic}, JSON::PP::false, 'republish overwrites stale policy');

# directory mode when created
my $dir_st = stat($root);
is($dir_st->mode & 07777, 0700, 'newly created policy directory is 0700');

PVE::QemuServer::DiagnosticCapture::remove_policy(111, $root);
ok(!-e $path, 'remove_policy deletes the file');

eval { PVE::QemuServer::DiagnosticCapture::remove_policy(111, $root) };
is($@, '', 'remove_policy is idempotent for missing files');

# ---------------------------------------------------------------------------
# machine_supports_pvpanic
# ---------------------------------------------------------------------------

ok(PVE::QemuServer::DiagnosticCapture::machine_supports_pvpanic('pc', 'x86_64'),
    'i440fx pc supported');
ok(PVE::QemuServer::DiagnosticCapture::machine_supports_pvpanic('pc-i440fx-8.1', 'x86_64'),
    'versioned i440fx supported');
ok(PVE::QemuServer::DiagnosticCapture::machine_supports_pvpanic('q35', 'x86_64'),
    'q35 supported');
ok(PVE::QemuServer::DiagnosticCapture::machine_supports_pvpanic('pc-q35-9.2', 'x86_64'),
    'versioned q35 supported');
ok(!PVE::QemuServer::DiagnosticCapture::machine_supports_pvpanic('virt', 'x86_64'),
    'virt machine not supported');
ok(!PVE::QemuServer::DiagnosticCapture::machine_supports_pvpanic(undef, 'x86_64'),
    'undefined machine not supported');
ok(!PVE::QemuServer::DiagnosticCapture::machine_supports_pvpanic('pc', 'aarch64'),
    'non-x86 architecture not supported');
ok(PVE::QemuServer::DiagnosticCapture::machine_supports_pvpanic('type=pc', 'x86_64'),
    'property-style machine string accepted');

# ---------------------------------------------------------------------------
# find_pvpanic_conflict
# ---------------------------------------------------------------------------

is(
    PVE::QemuServer::DiagnosticCapture::find_pvpanic_conflict(undef, undef),
    undef,
    'no conflict without args/cpu',
);

is(
    PVE::QemuServer::DiagnosticCapture::find_pvpanic_conflict([], 'host'),
    undef,
    'no conflict for unrelated args',
);

like(
    PVE::QemuServer::DiagnosticCapture::find_pvpanic_conflict(
        ['-action', 'panic=shutdown'], undef
    ),
    qr/panic/i,
    'conflict detected for existing -action panic policy',
);

like(
    PVE::QemuServer::DiagnosticCapture::find_pvpanic_conflict(
        ['-device', 'pvpanic-pci,id=foo'], undef
    ),
    qr/pvpanic/i,
    'conflict detected for an existing pvpanic-pci device',
);

like(
    PVE::QemuServer::DiagnosticCapture::find_pvpanic_conflict(['-device', 'pvpanic'], undef),
    qr/pvpanic/i,
    'conflict detected for an existing isa pvpanic device',
);

is(
    PVE::QemuServer::DiagnosticCapture::find_pvpanic_conflict(
        ['-device', 'virtio-net-pci'], undef
    ),
    undef,
    'unrelated -device does not conflict',
);

is(
    PVE::QemuServer::DiagnosticCapture::find_pvpanic_conflict(
        ['-action', 'reboot=reset'], undef
    ),
    undef,
    'non-panic -action does not conflict',
);

like(
    PVE::QemuServer::DiagnosticCapture::find_pvpanic_conflict(undef, 'host,hv-crash'),
    qr/hv-crash/i,
    'conflict detected for cpu hv-crash flag',
);

is(
    PVE::QemuServer::DiagnosticCapture::find_pvpanic_conflict(undef, 'host,+aes'),
    undef,
    'cpu flags without hv-crash do not conflict',
);

# ---------------------------------------------------------------------------
# device strings / action args
# ---------------------------------------------------------------------------

is(
    PVE::QemuServer::DiagnosticCapture::pvpanic_device_string(),
    'pvpanic-pci,id=pvpanic0',
    'pvpanic device string without pci address',
);

is(
    PVE::QemuServer::DiagnosticCapture::pvpanic_device_string(',bus=pci.1,addr=0x1f'),
    'pvpanic-pci,id=pvpanic0,bus=pci.1,addr=0x1f',
    'pvpanic device string with pci address',
);

is_deeply(
    [PVE::QemuServer::DiagnosticCapture::pvpanic_action_args()],
    ['-action', 'panic=none'],
    'panic action is report-only (-action panic=none)',
);

# ---------------------------------------------------------------------------
# cpu_enables_hv_crash / find_pvpanic_conflict variants
# ---------------------------------------------------------------------------

ok(!PVE::QemuServer::DiagnosticCapture::cpu_enables_hv_crash(undef),
    'undefined cpu does not enable hv-crash');
ok(!PVE::QemuServer::DiagnosticCapture::cpu_enables_hv_crash('host'),
    'plain cpu type does not enable hv-crash');
ok(PVE::QemuServer::DiagnosticCapture::cpu_enables_hv_crash('host,hv-crash'),
    'comma separated hv-crash recognised');
ok(PVE::QemuServer::DiagnosticCapture::cpu_enables_hv_crash('host,+hv-crash'),
    'plus separated hv-crash recognised');
ok(PVE::QemuServer::DiagnosticCapture::cpu_enables_hv_crash('host,flags=+aes;+hv-crash'),
    'flags property with semicolon separator recognised');
ok(PVE::QemuServer::DiagnosticCapture::cpu_enables_hv_crash('host,flags=+hv-crash'),
    'flags property with trailing hv-crash recognised');
ok(PVE::QemuServer::DiagnosticCapture::cpu_enables_hv_crash('host,flags=+hv-crash;-aes'),
    'flags property with leading hv-crash recognised');
ok(!PVE::QemuServer::DiagnosticCapture::cpu_enables_hv_crash('host,flags=-hv-crash'),
    'explicitly disabled hv-crash is not a conflict');
ok(!PVE::QemuServer::DiagnosticCapture::cpu_enables_hv_crash('host,flags=+aes;-hv-crash'),
    'negated hv-crash after another flag is not a conflict');
ok(!PVE::QemuServer::DiagnosticCapture::cpu_enables_hv_crash('host,flags=+hv-crash-helper'),
    'a longer flag name is not mistaken for hv-crash');

like(
    PVE::QemuServer::DiagnosticCapture::find_pvpanic_conflict(
        ['-cpu', 'host,flags=+hv-crash'], undef
    ),
    qr/hv-crash/i,
    'conflict detected for explicit -cpu args enabling hv-crash',
);

is(
    PVE::QemuServer::DiagnosticCapture::find_pvpanic_conflict(
        ['-cpu', 'host,flags=+aes'], undef
    ),
    undef,
    'explicit -cpu args without hv-crash do not conflict',
);

like(
    PVE::QemuServer::DiagnosticCapture::find_pvpanic_conflict(
        undef, 'host,flags=+aes;+hv-crash'
    ),
    qr/hv-crash/i,
    'conflict detected for cpu flags property with semicolon separator',
);

is(
    PVE::QemuServer::DiagnosticCapture::find_pvpanic_conflict(
        undef, 'host,flags=-hv-crash'
    ),
    undef,
    'cpu explicitly disabling hv-crash is not a conflict',
);

# ---------------------------------------------------------------------------
# plan_create_capture_config
# ---------------------------------------------------------------------------

my $plan = PVE::QemuServer::DiagnosticCapture::plan_create_capture_config(
    { ostype => 'l26' }, 1, []);
is($plan->{defaults}->{pvpanic}, 1, 'eligible new VM defaults pvpanic on');
is($plan->{defaults}->{'diagnostic-capture'}, 'panic=1,heartbeat=1',
    'eligible new VM defaults capture on');
is_deeply($plan->{skipped}, {}, 'eligible new VM skips nothing');

my $plan_unsupported = PVE::QemuServer::DiagnosticCapture::plan_create_capture_config(
    { ostype => 'l26' }, 0, []);
is_deeply($plan_unsupported->{defaults}, {},
    'unsupported machine/arch defaults nothing');
like($plan_unsupported->{skipped}->{pvpanic}, qr/support/i,
    'unsupported machine/arch records why pvpanic was skipped');

my $conflict_args = ['-device', 'pvpanic-pci,id=foo'];
my $plan_conflict = PVE::QemuServer::DiagnosticCapture::plan_create_capture_config(
    { ostype => 'l26' }, 1, $conflict_args);
ok(!defined($plan_conflict->{defaults}->{pvpanic}),
    'conflicting user args are not auto-defaulted with pvpanic');
like($plan_conflict->{skipped}->{pvpanic}, qr/already adds a pvpanic device/i,
    'conflict reason is recorded');
is($plan_conflict->{defaults}->{'diagnostic-capture'}, 'panic=1,heartbeat=1',
    'pure collector capture policy is still defaulted despite device conflict');

my $plan_cpu_conflict = PVE::QemuServer::DiagnosticCapture::plan_create_capture_config(
    { ostype => 'l26', cpu => 'host,flags=+hv-crash' }, 1, []);
ok(!defined($plan_cpu_conflict->{defaults}->{pvpanic}),
    'cpu hv-crash conflict prevents pvpanic auto-default');

my $user_args = ['-action', 'panic=shutdown'];
my $user_args_copy = [@$user_args];
PVE::QemuServer::DiagnosticCapture::plan_create_capture_config(
    { ostype => 'l26' }, 1, $user_args);
is_deeply($user_args, $user_args_copy, 'plan never modifies the user args');

my $plan_explicit = PVE::QemuServer::DiagnosticCapture::plan_create_capture_config(
    { ostype => 'l26', pvpanic => 0, 'diagnostic-capture' => 'panic=0,heartbeat=0' },
    1, []);
is_deeply($plan_explicit->{defaults}, {},
    'explicit user choices are never overridden by defaults');
is_deeply($plan_explicit->{skipped}, {}, 'explicit user choices skip nothing');

my $plan_user_capture = PVE::QemuServer::DiagnosticCapture::plan_create_capture_config(
    { ostype => 'l26', 'diagnostic-capture' => 'panic=0' }, 1, []);
is($plan_user_capture->{defaults}->{pvpanic}, 1,
    'pvpanic still defaulted when only capture was overridden');
ok(!defined($plan_user_capture->{defaults}->{'diagnostic-capture'}),
    'user provided capture policy is kept');

eval {
    PVE::QemuServer::DiagnosticCapture::plan_create_capture_config(
        { ostype => 'l26', pvpanic => 1 }, 0, []);
};
like($@, qr/support/i, 'explicit pvpanic on unsupported machine/arch dies at plan time');

eval {
    PVE::QemuServer::DiagnosticCapture::plan_create_capture_config(
        { ostype => 'l26', pvpanic => 1 }, 1, ['-action', 'panic=shutdown']);
};
like($@, qr/already sets a panic policy/i,
    'explicit conflicting pvpanic dies instead of persisting a broken config');

eval {
    PVE::QemuServer::DiagnosticCapture::plan_create_capture_config(
        { ostype => 'l26', pvpanic => 1, cpu => 'host,flags=+hv-crash' }, 1, []);
};
like($@, qr/hv-crash/i, 'explicit pvpanic with hv-crash cpu dies');

# ---------------------------------------------------------------------------
# policy fail-safe: publish/remove must never fail open
# ---------------------------------------------------------------------------

my $fsroot = tempdir(CLEANUP => 1);

my $enabled = PVE::QemuServer::DiagnosticCapture::normalize_policy(
    900, capture => { panic => 1, heartbeat => 1 }, agent => 1);
PVE::QemuServer::DiagnosticCapture::publish_policy(900, $enabled, $fsroot);
my $enabled_path = "$fsroot/900.capture-policy.json";
ok(-f $enabled_path, 'enabled policy published');

# a publish that fails must not leave the previously enabled policy behind
srand(4242);
my $collide = int(rand(1_000_000));
my $collide_path = "$enabled_path.tmp.$$.$collide";
open(my $cfh, '>', $collide_path) or die "cannot create $collide_path: $!";
close($cfh);
srand(4242); # make publish pick the same temp name -> O_EXCL fails
my $publish_err = '';
eval {
    PVE::QemuServer::DiagnosticCapture::publish_policy(
        900,
        PVE::QemuServer::DiagnosticCapture::normalize_policy(
            900, capture => { panic => 0, heartbeat => 0 }, agent => 0),
        $fsroot,
    );
    1;
} or $publish_err = $@;
like($publish_err, qr/unable to create/, 'failed publish dies loudly');
ok(!-e $enabled_path,
    'failed publish does not leave an enabled policy behind (fail-safe)');

# remove_policy never reports success while a stale entry could not be disabled
my $stale_path = "$fsroot/901.capture-policy.json";
mkdir($stale_path) or die "mkdir $stale_path: $!";
my $remove_err = '';
eval { PVE::QemuServer::DiagnosticCapture::remove_policy(901, $fsroot); 1 }
    or $remove_err = $@;
ok(length($remove_err) > 0,
    'remove_policy dies when the stale entry cannot be neutralised');
ok(-d $stale_path, 'the unremovable stale entry is still reported, not hidden');
rmdir($stale_path);

# ---------------------------------------------------------------------------
# create-time precheck runs before any side effect (source order)
# ---------------------------------------------------------------------------

my $api2_src = do { local $/; open my $fh, '<', '../PVE/API2/Qemu.pm' or die $!; <$fh> };

my $createfn_start = index($api2_src, 'my $createfn = sub {');
my $createfn_end = index($api2_src, 'my ($code, $worker_name);');
ok($createfn_start >= 0 && $createfn_end > $createfn_start,
    'located the VM create path in API2/Qemu.pm');

my $createfn = substr($api2_src, $createfn_start, $createfn_end - $createfn_start);

my $plan_pos = index($createfn, 'plan_create_capture_config');
my $disks_pos = index($createfn, 'create_disks(');
my $write_pos = index($createfn, 'PVE::QemuConfig->write_config($vmid, $conf);');

ok($plan_pos >= 0, 'create path calls the capture precheck');
ok($plan_pos < $disks_pos,
    'capture precheck runs before disk creation (first side effect)');
ok($plan_pos < $write_pos,
    'capture precheck runs before the config is written');

# ---------------------------------------------------------------------------
# PVE::QemuServer integration (only with the full PVE Perl stack present)
# ---------------------------------------------------------------------------

subtest 'PVE::QemuServer policy integration' => sub {
    if (!eval { require PVE::QemuServer; 1 }) {
        plan skip_all => "PVE::QemuServer not fully available: $@";
    }

    my $root = tempdir(CLEANUP => 1);
    local $PVE::QemuServer::DiagnosticCapture::POLICY_DIR = $root;

    my $conf = { ostype => 'l26', agent => '1', 'diagnostic-capture' => 'panic=1,heartbeat=1' };
    PVE::QemuServer::publish_capture_policy(777, $conf);
    my $p = "$root/777.capture-policy.json";
    ok(-f $p, 'publish_capture_policy writes the runtime policy');

    my $read = sub {
        local $/;
        open my $fh, '<', $p or die "open $p: $!";
        return JSON::PP->new->decode(<$fh>);
    };

    is($read->()->{panic}, JSON::PP::true, 'policy reflects the effective panic capture');
    is($read->()->{heartbeat}, JSON::PP::true, 'policy reflects effective heartbeat with agent');

    # pending changes must never be applied to the running policy / any pending
    # (non capture) device change must not leak into the policy
    $conf->{'diagnostic-capture'} = 'panic=0,heartbeat=0';
    $conf->{pending} = {
        'diagnostic-capture' => 'panic=1,heartbeat=1',
        pvpanic => 1,
        watchdog => 'model=i6300esb',
    };
    PVE::QemuServer::publish_capture_policy(777, $conf);
    is($read->()->{panic}, JSON::PP::false,
        'policy follows the effective value, never the pending one');

    ok(PVE::QemuServer::pvpanic_supported({ machine => 'pc' }, 'x86_64'),
        'pvpanic_supported true for x86_64 i440fx');
    ok(PVE::QemuServer::pvpanic_supported({ machine => 'q35' }, 'x86_64'),
        'pvpanic_supported true for q35');
    ok(!PVE::QemuServer::pvpanic_supported({ machine => 'virt' }, 'aarch64'),
        'pvpanic_supported false for aarch64 virt');

    PVE::QemuServer::remove_capture_policy(777);
    ok(!-e $p, 'remove_capture_policy clears the runtime policy');
};

done_testing();
