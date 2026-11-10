package PVE::QemuServer::DiagnosticCapture;

# Pure-Perl helper for the runtime diagnostic-capture policy.
#
# This module is intentionally free of PVE dependencies so that its policy
# normalization and the atomic on-disk publication can be unit tested without a
# full Proxmox VE installation. The qemu-server integration (schema parsing,
# machine/agent inspection) lives in PVE::QemuServer and passes plain values in.

use strict;
use warnings;

use Fcntl qw(O_WRONLY O_CREAT O_EXCL O_NOFOLLOW);
use File::Basename qw(dirname);
use File::Path qw(make_path);
use JSON::PP;

# Policy defaults, see the capture implementation contract.
my $POLICY_VERSION = 1;
my $DEFAULT_HEARTBEAT_INTERVAL = 10;
my $DEFAULT_HEARTBEAT_TIMEOUT = 3;
my $DEFAULT_FAILURE_THRESHOLD = 3;
my $DEFAULT_RECOVERY_THRESHOLD = 2;
my $DEFAULT_GRACE_PERIOD = 60;
my $DEFAULT_SCREENSHOT_TIMEOUT = 5;

my $DEFAULT_POLICY_DIR = '/run/qemu-server';

# Test seam only: the runtime policy directory. Production always uses the
# compiled-in default; unit tests inject a private directory.
our $POLICY_DIR = $DEFAULT_POLICY_DIR;

# Parse a boolean-ish property value the same way PVE's schema checker does.
my $parse_bool = sub {
    my ($value) = @_;
    return 0 if !defined($value);
    return 1 if $value eq '1' || $value =~ m/^(on|yes|true)$/i;
    return 0 if $value eq '0' || $value =~ m/^(off|no|false)$/i;
    return 0;
};

# Parse the "diagnostic-capture" property string, e.g. "panic=1,heartbeat=1".
# Missing/invalid values default to off and never throw.
sub parse_capture_string {
    my ($value) = @_;

    my $res = { panic => 0, heartbeat => 0 };
    return $res if !defined($value) || $value eq '';

    for my $part (split(/\s*,\s*/, $value)) {
        next if $part eq '';
        my ($key, $val) = split(/\s*=\s*/, $part, 2);
        next if !defined($key) || !defined($val);
        next if $key ne 'panic' && $key ne 'heartbeat';
        $res->{$key} = $parse_bool->($val);
    }

    return $res;
}

# Build the normalized runtime policy hash from already-resolved inputs.
#   capture     => property string or hashref { panic => 0|1, heartbeat => 0|1 }
#   agent       => whether the QEMU guest agent is enabled in the effective config
#   maintenance => whether the VM is currently in a maintenance window
sub normalize_policy {
    my ($vmid, %opts) = @_;

    die "invalid vmid '$vmid' for diagnostic capture policy\n"
        if !defined($vmid) || $vmid !~ m/^\d+$/;

    my $capture = $opts{capture};
    my $parsed;
    if (ref($capture) eq 'HASH') {
        $parsed = {
            panic => $capture->{panic} ? 1 : 0,
            heartbeat => $capture->{heartbeat} ? 1 : 0,
        };
    } else {
        $parsed = parse_capture_string($capture);
    }

    my $agent = $opts{agent} ? 1 : 0;
    my $maintenance = $opts{maintenance} ? 1 : 0;

    # heartbeat capture additionally requires an enabled guest agent
    my $heartbeat = ($parsed->{heartbeat} && $agent) ? 1 : 0;

    return {
        version => $POLICY_VERSION,
        vmid => int($vmid),
        panic => $parsed->{panic} ? JSON::PP::true : JSON::PP::false,
        heartbeat => $heartbeat ? JSON::PP::true : JSON::PP::false,
        agent => $agent ? JSON::PP::true : JSON::PP::false,
        maintenance => $maintenance ? JSON::PP::true : JSON::PP::false,
        heartbeat_interval => $DEFAULT_HEARTBEAT_INTERVAL,
        heartbeat_timeout => $DEFAULT_HEARTBEAT_TIMEOUT,
        failure_threshold => $DEFAULT_FAILURE_THRESHOLD,
        recovery_threshold => $DEFAULT_RECOVERY_THRESHOLD,
        grace_period => $DEFAULT_GRACE_PERIOD,
        screenshot_timeout => $DEFAULT_SCREENSHOT_TIMEOUT,
    };
}

sub policy_path {
    my ($vmid, $root) = @_;

    die "invalid vmid '$vmid' for diagnostic capture policy\n"
        if !defined($vmid) || $vmid !~ m/^\d+$/;

    $root //= $POLICY_DIR;
    return "$root/$vmid.capture-policy.json";
}

# Atomically publish the normalized policy for $vmid. Creates the policy
# directory (root-owned 0700) if needed and writes a root-owned 0600 file via a
# unique temporary file plus rename, so readers never observe a partial file.
#
# Fail-safe direction: if publishing fails, a previously published policy for
# this VMID must not keep diagnostics enabled. We therefore neutralise any
# stale policy before propagating the error.
sub publish_policy {
    my ($vmid, $policy, $root) = @_;

    die "publish_policy requires a policy hash\n" if ref($policy) ne 'HASH';

    $root //= $POLICY_DIR;
    my $path = policy_path($vmid, $root);

    if (!-d $root) {
        make_path($root, { mode => 0700 });
    }

    my $json = JSON::PP->new->canonical(1)->encode($policy);
    $json .= "\n";

    my $data = $json;
    my $tmpname = "$path.tmp.$$." . int(rand(1_000_000));
    my $err;
    eval {
        my $fh;
        sysopen($fh, $tmpname, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600)
            or die "unable to create '$tmpname' - $!\n";
        binmode($fh);
        my $offset = 0;
        my $len = length($data);
        while ($offset < $len) {
            my $written = syswrite($fh, $data, $len - $offset, $offset);
            die "unable to write '$tmpname' - $!\n" if !defined($written);
            $offset += $written;
        }
        close($fh)
            or die "closing '$tmpname' failed - $!\n";
        # mode argument to sysopen is masked by umask, enforce exact 0600
        chmod(0600, $tmpname)
            or die "unable to chmod '$tmpname' - $!\n";
        rename($tmpname, $path)
            or die "unable to rename '$tmpname' to '$path' - $!\n";
    };
    if (my $e = $@) {
        $err = $e;
        unlink($tmpname) if defined($tmpname) && -e $tmpname;
    }

    if (defined($err)) {
        # never leave an (older, possibly enabled) policy in place after a
        # failed publish - disable diagnostics instead of failing open. This
        # is a direct unlink (not remove_policy) on purpose, to stay free of
        # recursion when the fallback itself fails.
        eval { unlink($path) };
        die $err;
    }

    return $path;
}

# Neutralise the runtime policy: remove the file, and if it cannot be removed
# (e.g. a leftover directory or permission problem) overwrite it with a
# disabled policy so that no stale *enabled* policy survives VM deletion or
# VMID reuse. Dies only when the policy could not be disabled at all.
sub remove_policy {
    my ($vmid, $root) = @_;

    $root //= $POLICY_DIR;
    my $path = policy_path($vmid, $root);

    return 1 if !-e $path && !-l $path;

    if (unlink($path)) {
        return 1 if !-e $path;
    }

    # unlink() did not get rid of it - overwrite with an explicit disabled
    # policy via the atomic rename path, which also works if $path is a
    # regular file we are not allowed to unlink but may replace.
    my $disabled = normalize_policy($vmid, capture => { panic => 0, heartbeat => 0 }, agent => 0);
    publish_policy($vmid, $disabled, $root);

    return 1;
}

# Support gate for the pvpanic device: only x86 i440fx/q35 machines.
# $machine_type is the resolved machine type (e.g. "pc", "pc-i440fx-8.1", "q35").
sub machine_supports_pvpanic {
    my ($machine_type, $arch) = @_;

    $arch //= 'x86_64';
    return 0 if $arch ne 'x86_64';
    return 0 if !defined($machine_type) || $machine_type eq '';

    my $type = $machine_type;
    $type = $1 if $type =~ m/^type=([^,]+)/;

    return 1 if $type =~ m/^(?:pc|q35)(?:-|$)/;
    return 0;
}

# Does a PVE CPU configuration string already request QEMU's 'hv-crash'
# Hyper-V flag (which itself enables panic notification and would collide with
# the managed pvpanic-pci device)?
#
# PVE CPU strings are property strings: properties are separated by ',', while
# the 'flags' property uses ';' between individual flags, e.g.
#   "host,flags=+aes;+hv-crash"
# A leading '-' disables a flag and is not a conflict. Explicit QEMU arguments
# can also carry a raw '-cpu ...' string with the same flag syntax.
sub cpu_enables_hv_crash {
    my ($cpu) = @_;

    return 0 if !defined($cpu) || $cpu eq '';

    return $cpu =~ m/(?:^|[+,;])hv-crash(?:[+,;]|$)/ ? 1 : 0;
}

# Detect explicit conflicting QEMU arguments that would collide with the
# managed pvpanic device. Accepts the split argument list and the CPU config
# string. Returns an error string if there is a conflict, undef otherwise.
sub find_pvpanic_conflict {
    my ($args, $cpu) = @_;

    if (ref($args) eq 'ARRAY') {
        for my $i (0 .. $#$args) {
            my $token = $args->[$i];
            next if !defined($token);

            if ($token eq '-action' && defined($args->[$i + 1])) {
                return "explicit '-action $args->[$i + 1]' already sets a panic policy"
                    if $args->[$i + 1] =~ m/(?:^|,)panic=/;
            }

            if ($token eq '-device' && defined($args->[$i + 1])) {
                return "explicit '-device $args->[$i + 1]' already adds a pvpanic device"
                    if $args->[$i + 1] =~ m/^pvpanic(?:-pci)?(?:,|$)/;
            }

            if ($token eq '-cpu' && defined($args->[$i + 1])) {
                return "explicit '-cpu $args->[$i + 1]' already enables 'hv-crash'"
                    if cpu_enables_hv_crash($args->[$i + 1]);
            }
        }
    }

    return "cpu config already enables 'hv-crash'" if cpu_enables_hv_crash($cpu);

    return undef;
}

# Plan the capture defaults for a *newly created* VM.
#
#   $conf      - the validated create parameters (hash reference)
#   $supported - whether the resolved arch/machine supports the managed
#                pvpanic device (see machine_supports_pvpanic)
#   $args      - the user's explicit QEMU arguments, already split into a list
#                (array reference, may be undef)
#
# Returns:
#   { defaults => { key => value, ... },   # eligible, conflict-free defaults
#     skipped  => { key => reason, ... } } # intentionally not defaulted
#
# Dies when pvpanic was requested explicitly but cannot be honoured
# (unsupported machine/arch, or a conflict with the user's own args/cpu), so
# that a create can never persist a configuration that would make the VM fail
# to start. It never modifies the user's arguments.
sub plan_create_capture_config {
    my ($conf, $supported, $args) = @_;

    die "plan_create_capture_config requires a config hash\n" if ref($conf) ne 'HASH';

    my $res = { defaults => {}, skipped => {} };

    my $explicit_pvpanic = defined($conf->{pvpanic}) ? ($conf->{pvpanic} ? 1 : 0) : undef;

    if (defined($explicit_pvpanic) && $explicit_pvpanic) {
        die "pvpanic was requested explicitly, but the configured"
            . " machine/architecture does not support the pvpanic-pci device\n"
            if !$supported;

        my $conflict = find_pvpanic_conflict($args, $conf->{cpu});
        die "pvpanic was requested explicitly, but $conflict - refusing to persist a"
            . " configuration that would make the VM fail to start\n"
            if $conflict;
    } elsif (!defined($explicit_pvpanic) && $supported) {
        my $conflict = find_pvpanic_conflict($args, $conf->{cpu});
        if ($conflict) {
            # do not auto-add a device the user's own arguments already conflict
            # with - the VM would otherwise never start
            $res->{skipped}->{pvpanic} = $conflict;
        } else {
            $res->{defaults}->{pvpanic} = 1;
        }
    } elsif (!defined($explicit_pvpanic)) {
        $res->{skipped}->{pvpanic} = 'machine/architecture does not support pvpanic-pci';
    }

    # The capture policy itself is a pure collector setting: it never changes a
    # guest device and can therefore be defaulted on for eligible VMs even when
    # the pvpanic device itself could not be added.
    $res->{defaults}->{'diagnostic-capture'} = 'panic=1,heartbeat=1'
        if $supported && !defined($conf->{'diagnostic-capture'});

    return $res;
}

sub pvpanic_device_string {
    my ($pciaddr) = @_;
    $pciaddr //= '';
    return "pvpanic-pci,id=pvpanic0$pciaddr";
}

sub pvpanic_action_args {
    return ('-action', 'panic=none');
}

1;
