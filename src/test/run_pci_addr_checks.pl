#!/usr/bin/perl

use strict;
use warnings;
use experimental 'smartmatch';

use lib qw(..);

use Test::More;

use PVE::Tools qw(file_get_contents);
use PVE::QemuServer::PCI;

my $qemu_cfg_base_path = "../usr";

# not our format but that what QEMU gets passed with '-readconfig'
sub slurp_qemu_config {
    my ($fn) = @_;

    my $raw = file_get_contents($fn);

    my $lineno = 0;
    my $cfg = {};
    my $group;
    my $skip_to_next_group;
    while ($raw =~ /^\h*(.*?)\h*$/gm) {
        my $line = $1;
        $lineno++;
        next if !$line || $line =~ /^#/;

        # tried to follow qemu's qemu_config_parse function
        if ($line =~ /\[(\S{1,63}) "([^"\]]{1,63})"\]/) {
            $group = $2;
            $skip_to_next_group = 0;
            if ($1 ne 'device') {
                $group = undef;
                $skip_to_next_group = 1;
            }
        } elsif ($line =~ /\[([^\]]{1,63})\]/) {
            $group = undef;
            $skip_to_next_group = 1;
        } elsif ($group) {
            if ($line =~ /(\S{1,63}) = "([^\"]{1,1023})"/) {
                my ($k, $v) = ($1, $2);
                $cfg->{$group}->{$k} = $v;
            } else {
                print "ignoring $fn:$lineno: $line\n";
            }
        } else {
            warn "ignore $fn:$lineno, currently no group\n" if !$skip_to_next_group;
        }
    }

    return $cfg;
}

sub extract_qemu_config_addrs {
    my ($qemu_cfg) = @_;

    my $addr_map = {};
    for my $k (keys %$qemu_cfg) {
        my $v = $qemu_cfg->{$k};
        next if !$v || !defined($v->{bus}) || !defined($v->{addr});

        my $bus = $v->{bus};
        $bus =~ s/pci\.//;

        $addr_map->{$k} = { bus => $bus, addr => $v->{addr} };
    }

    return $addr_map;
}

print "testing PCI(e) address conflicts\n";

# exec tests

#FIXME: make cross PCI <-> PCIe check sense at all??
my $addr_map = {};
my ($fail, $ignored) = (0, 0);

sub check_conflict {
    my ($id, $what, $ignore_if_same_key) = @_;

    my ($bus, $addr) = $what->@{qw(bus addr)};
    my $full_addr = "$bus:$addr";

    if (defined(my $conflict = $addr_map->{$full_addr})) {
        if (my @ignores = $what->{conflict_ok}) {
            if ($conflict ~~ @ignores) {
                note("OK: ignore conflict for '$full_addr' between '$id' and '$conflict'");
                $ignored++;
                return;
            }
        }
        # this allows to read multiple pve-*.cfg qemu configs, and check them
        # normally their OK if they conflict is on the same key. Else TODO??
        return if $ignore_if_same_key && $id eq $conflict;

        note("ERR: conflict for '$full_addr' between '$id' and '$conflict'");
        $fail++;
    } else {
        $addr_map->{$full_addr} = $id;
    }
}

# NOTE: get_pci_addr_map() called *without* an architecture argument actually
# returns the aarch64 map (the function treats any arch != x86_64 as non-x86).
# The x86_64 map - which is the one the managed pvpanic-pci device uses - was
# therefore never conflict-checked. Check both architectures explicitly.
sub check_arch_conflicts {
    my ($arch) = @_;

    $addr_map = {};

    my $arch_pci_map = PVE::QemuServer::PCI::get_pci_addr_map($arch);
    while (my ($id, $what) = each %$arch_pci_map) {
        check_conflict($id, $what);
    }

    my $arch_pcie_map = PVE::QemuServer::PCI::get_pcie_addr_map();
    while (my ($id, $what) = each %$arch_pcie_map) {
        check_conflict($id, $what);
    }
}

sub check_conflict_free {
    my ($arch) = @_;

    check_arch_conflicts($arch);

    my $pve_cfg = slurp_qemu_config("$qemu_cfg_base_path/pve-q35.cfg");
    my $pve_cfg_map = extract_qemu_config_addrs($pve_cfg);
    while (my ($id, $what) = each %$pve_cfg_map) {
        check_conflict($id, $what);
    }
}

# x86_64 first so the shipped pve-q35 qemu config is cross-checked against the
# map that actually applies on x86_64.
check_conflict_free('x86_64');

# FIXME: restart with clean conflict $addr_map with only get_pci*_addr_map ones?
my $pve_qm4_cfg = slurp_qemu_config("$qemu_cfg_base_path/pve-q35-4.0.cfg");
my $pve_qm4_cfg_map = extract_qemu_config_addrs($pve_qm4_cfg);
while (my ($id, $what) = each %$pve_qm4_cfg_map) {
    check_conflict($id, $what, 1);
}
my $pve_qm_usb_cfg = slurp_qemu_config("$qemu_cfg_base_path/pve-usb.cfg");
my $pve_qm_usb_cfg_map = extract_qemu_config_addrs($pve_qm_usb_cfg);
while (my ($id, $what) = each %$pve_qm_usb_cfg_map) {
    check_conflict($id, $what, 1);
}

# the aarch64 map is checked on its own as well
check_arch_conflicts('aarch64');

if ($fail) {
    fail("PCI(e) address conflict check, ignored: $ignored, conflicts: $fail");
} else {
    pass("PCI(e) address conflict check, ignored: $ignored");
}

# the managed pvpanic-pci device lives on a fixed, dedicated x86_64 slot
my $x86_map = PVE::QemuServer::PCI::get_pci_addr_map('x86_64');
is_deeply(
    $x86_map->{pvpanic},
    { bus => 1, addr => 31 },
    'x86_64 pvpanic slot is the fixed pci.1 addr 0x1f',
);
is(
    PVE::QemuServer::PCI::print_pci_addr('pvpanic', undef, 'x86_64'),
    ',bus=pci.1,addr=0x1f',
    'x86_64 pvpanic prints the fixed address',
);

# pvpanic-pci must not be usable on architectures it is not wired for
my $arm_map = PVE::QemuServer::PCI::get_pci_addr_map('aarch64');
ok(!exists $arm_map->{pvpanic}, 'aarch64 has no pvpanic slot');

done_testing();
