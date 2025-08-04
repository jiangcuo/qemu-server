package PVE::QemuServer::PCI;

use warnings;
use strict;

use IO::File;

use PVE::JSONSchema;
use PVE::Mapping::PCI;
use PVE::SysFSTools;
use PVE::Tools qw(dir_glob_foreach run_command);
use PVE::JSONSchema qw(get_standard_option parse_property_string);
use Cwd 'realpath';
use File::Basename;

use PVE::QemuServer::Helpers;
use PVE::QemuServer::Machine;

use base 'Exporter';

our @EXPORT_OK = qw(
    print_pci_addr
    print_pcie_addr
    print_pcie_root_port
    print_pcie_root_port_for_port
    parse_hostpci
);

our $MAX_HOSTPCI_DEVICES = 16;

my $PCIRE = qr/(?:[a-f0-9]{4,}:)?[a-f0-9]{2}:[a-f0-9]{2}(?:\.[a-f0-9])?/;
my $hostpci_fmt = {
    host => {
        default_key => 1,
        optional => 1,
        type => 'string',
        pattern => qr/$PCIRE(;$PCIRE)*/,
        format_description => 'HOSTPCIID[;HOSTPCIID2...]',
        description => <<EODESCR,
Host PCI device pass through. The PCI ID of a host's PCI device or a list
of PCI virtual functions of the host. HOSTPCIID syntax is:

'bus:dev.func' (hexadecimal numbers)

You can use the 'lspci' command to list existing PCI devices.

Either this or the 'mapping' key must be set.
EODESCR
    },
    mapping => {
        optional => 1,
        type => 'string',
        format_description => 'mapping-id',
        format => 'pve-configid',
        description => "The ID of a cluster wide mapping. Either this or the default-key 'host'"
            . " must be set.",
    },
    mac => get_standard_option('mac-addr', {
        description => "MAC address. That address must be unique within your network. This is"
            ." automatically generated if not specified.",
        },
        optional => 1,
    ),
    tag => {
        type => 'integer',
        minimum => 1, maximum => 4094,
        description => 'VLAN tag to apply to packets on this interface.',
        optional => 1,
    },
    ramfb => {
        type => 'boolean',
        description =>  "Show mdev device's ramfb",
        optional => 1,
        default => 1,
    },
    rombar => {
        type => 'boolean',
        description => "Specify whether or not the device's ROM will be visible in the"
            . " guest's memory map.",
        optional => 1,
        default => 1,
    },
    romfile => {
        type => 'string',
        pattern => '[^,;]+',
        format_description => 'string',
        description => "Custom pci device rom filename (must be located in /usr/share/kvm/).",
        optional => 1,
    },
    pcie => {
        type => 'boolean',
        description => "Choose the PCI-express bus (needs the 'q35' machine model).",
        optional => 1,
        default => 0,
    },
    'x-vga' => {
        type => 'boolean',
        description => "Enable vfio-vga device support.",
        optional => 1,
        default => 0,
    },
    'legacy-igd' => {
        type => 'boolean',
        description =>
            "Pass this device in legacy IGD mode, making it the primary and exclusive"
            . " graphics device in the VM. Requires 'pc-i440fx' machine type and VGA set to 'none'.",
        optional => 1,
        default => 0,
    },
    'mdev' => {
        type => 'string',
        format_description => 'string',
        pattern => '[^/\.:]+',
        optional => 1,
        description => <<EODESCR,
The type of mediated device to use.
An instance of this type will be created on startup of the VM and
will be cleaned up when the VM stops.
EODESCR
    },
    'vendor-id' => {
        type => 'string',
        pattern => qr/^0x[0-9a-fA-F]{4}$/,
        format_description => 'hex id',
        optional => 1,
        description => "Override PCI vendor ID visible to guest",
    },
    'device-id' => {
        type => 'string',
        pattern => qr/^0x[0-9a-fA-F]{4}$/,
        format_description => 'hex id',
        optional => 1,
        description => "Override PCI device ID visible to guest",
    },
    'sub-vendor-id' => {
        type => 'string',
        pattern => qr/^0x[0-9a-fA-F]{4}$/,
        format_description => 'hex id',
        optional => 1,
        description => "Override PCI subsystem vendor ID visible to guest",
    },
    'sub-device-id' => {
        type => 'string',
        pattern => qr/^0x[0-9a-fA-F]{4}$/,
        format_description => 'hex id',
        optional => 1,
        description => "Override PCI subsystem device ID visible to guest",
    },
};
PVE::JSONSchema::register_format('pve-qm-hostpci', $hostpci_fmt);

our $hostpcidesc = {
    optional => 1,
    type => 'string',
    format => 'pve-qm-hostpci',
    description => "Map host PCI devices into guest.",
    verbose_description => <<EODESCR,
Map host PCI devices into guest.

NOTE: This option allows direct access to host hardware. So it is no longer
possible to migrate such machines - use with special care.

CAUTION: Experimental! User reported problems with this option.
EODESCR
};
PVE::JSONSchema::register_standard_option("pve-qm-hostpci", $hostpcidesc);

my $pci_addr_map;

sub get_pci_addr_map {
    my ($arch) = @_;
    if ($arch ne 'x86_64'){
        $pci_addr_map = {
            piix3 => { bus => 0, addr => 1, conflict_ok => qw(ehci)  },
            ehci => { bus => 0, addr => 1, conflict_ok => qw(piix3) }, # instead of piix3 on arm
            vga => { bus => 0, addr => 2, conflict_ok => qw(legacy-igd) },
            'legacy-igd' => { bus => 0, addr => 2, conflict_ok => qw(vga) }, # legacy-igd requires vga=none
            balloon0 => { bus => 0, addr => 3 },
            watchdog => { bus => 0, addr => 4 },
            scsihw0 => { bus => 0, addr => 5 },
            scsihw1 => { bus => 0, addr => 6 },
            ahci0 => { bus => 0, addr => 7 },
            qga0 => { bus => 0, addr => 8 },
            spice => { bus => 0, addr => 9 },
            'xhci' => { bus => 0, addr => 10 }, # Some operating systems support only PCI.0 addresses, such as windows
            # net0 will not be hotpluged, This is a legacy issue, and if the addr is modified during the update, 
            # it may cause the guest to lose internet access.
            # So we reserved this address for net0.
            # If you wan't eth0 support hotplug, please refer to the comments below
            'net0' => { bus => 0, addr => 11 }, 
            # pci 1 -> pcie.1 bus => 0, addr => 12 for net hotplug
            # pci 2 -> pcie.1 bus => 0, addr => 13 for virtio hotplug
            # pci 3 -> pcie.1 bus => 0, addr => 14 for virtioscsi0 hotplug
            # pci 4 -> pcie.1 bus => 0, addr => 15. Keep it for later, maybe it will be used by nvme
            hostpci0 => { bus => 5, addr => 0 },  	# pcie-port 5 -> pcie.5 bus => 0, addr => 16
            hostpci1 => { bus => 6, addr => 0 },    # pcie-port 6 -> pcie.6 bus => 0, addr => 17
            hostpci2 => { bus => 7, addr => 0 },    # pcie-port 7 -> pcie.7 bus => 0, addr => 18
            hostpci3 => { bus => 8, addr => 0 },    # pcie-port 8 -> pcie.8 bus => 0, addr => 19
            hostpci4 => { bus => 9, addr => 0 },    # pcie-port 9 -> pcie.9 bus => 0, addr => 20
            hostpci5 => { bus => 10, addr => 0 },   # pcie-port 10 -> pcie.10 bus => 0, addr => 21
            hostpci6 => { bus => 11, addr => 0 },   # pcie-port 11 -> pcie.11 bus => 0, addr => 22
            hostpci7 => { bus => 12, addr => 0 },   # pcie-port 12 -> pcie.12 bus => 0, addr => 23
            hostpci8 => { bus => 13, addr => 0 },   # pcie-port 13 -> pcie.13 bus => 0, addr => 24
            hostpci9 => { bus => 14, addr => 0 },   # pcie-port 14 -> pcie.14 bus => 0, addr => 25 
            hostpci10 => { bus => 15, addr => 0 },  # pcie-port 15 -> pcie.15 bus => 0, addr => 26 
            hostpci11 => { bus => 16, addr => 0 },  # pcie-port 16 -> pcie.16 bus => 0, addr => 27 
            hostpci12 => { bus => 17, addr => 0 },  # pcie-port 17 -> pcie.17 bus => 0, addr => 28 
            hostpci13 => { bus => 18, addr => 0 },  # pcie-port 18 -> pcie.18 bus => 0, addr => 29 
            hostpci14 => { bus => 19, addr => 0 },  # pcie-port 19 -> pcie.19 bus => 0, addr => 30 
            'rng0' => { bus => 0, addr => 31 },
            # 'net0' => { bus => 1, addr => 3 }, This support net0 hotplug
            'net1' => { bus => 1, addr => 4 },
            'net2' => { bus => 1, addr => 5 },
            'net3' => { bus => 1, addr => 6 },
            'net4' => { bus => 1, addr => 7 },
            'net5' => { bus => 1, addr => 8 },
            'net6' => { bus => 1, addr => 9 },
            'net7' => { bus => 1, addr => 10 },
            'net8' => { bus => 1, addr => 11 },
            'net9' => { bus => 1, addr => 12 },
            'net10' => { bus => 1, addr => 13 },
            'net11' => { bus => 1, addr => 14 },
            'net12' => { bus => 1, addr => 15 },
            'net13' => { bus => 1, addr => 16 },
            'net14' => { bus => 1, addr => 17 },
            'net15' => { bus => 1, addr => 18 },
            'net16' => { bus => 1, addr => 19 },
            'net17' => { bus => 1, addr => 20 },
            'net18' => { bus => 1, addr => 21 },
            'net19' => { bus => 1, addr => 22 },
            'net20' => { bus => 1, addr => 23 },
            'net21' => { bus => 1, addr => 24 },
            'net22' => { bus => 1, addr => 25 },
            'net23' => { bus => 1, addr => 26 },
            'net24' => { bus => 1, addr => 27 },	
            'vga1' => { bus => 1, addr => 28 },
            'vga2' => { bus => 1, addr => 29 },
            'pci.2-igd' => { bus => 1, addr => 30 }, # replaces pci.2 in case a legacy IGD device is passed through
            'virtio0' => { bus => 2, addr => 1 },
            'virtio1' => { bus => 2, addr => 2 },
            'virtio2' => { bus => 2, addr => 3 },
            'virtio3' => { bus => 2, addr => 4 },
            'virtio4' => { bus => 2, addr => 5 },
            'virtio5' => { bus => 2, addr => 6 },
            'virtio6' => { bus => 2, addr => 7 },
            'virtio7' => { bus => 2, addr => 8 },
            'virtio8' => { bus => 2, addr => 9 },
            'virtio9' => { bus => 2, addr => 10 },
            'virtio10' => { bus => 2, addr => 11 },
            'virtio11' => { bus => 2, addr => 12 },
            'virtio12' => { bus => 2, addr => 13 },
            'virtio13' => { bus => 2, addr => 14 },
            'virtio14' => { bus => 2, addr => 15 },
            'virtio15' => { bus => 2, addr => 16 },
            'ivshmem' => { bus => 2, addr => 17 },
            'audio0' => { bus => 2, addr => 18 },
            'scsihw2' => { bus => 2, addr => 19 },
            'scsihw3' => { bus => 2, addr => 20 },
            'scsihw4' => { bus => 2, addr => 21 },
            'spdk0' => { bus => 2, addr => 22 },
            'spdk1' => { bus => 2, addr => 23 },
            'spdk2' => { bus => 2, addr => 24 },
            'spdk3' => { bus => 2, addr => 25 },
            'spdk4' => { bus => 2, addr => 26 },
            'spdk5' => { bus => 2, addr => 27 },
            'virtioscsi0' => { bus => 3, addr => 1 },
            'virtioscsi1' => { bus => 3, addr => 2 },
            'virtioscsi2' => { bus => 3, addr => 3 },
            'virtioscsi3' => { bus => 3, addr => 4 },
            'virtioscsi4' => { bus => 3, addr => 5 },
            'virtioscsi5' => { bus => 3, addr => 6 },
            'virtioscsi6' => { bus => 3, addr => 7 },
            'virtioscsi7' => { bus => 3, addr => 8 },
            'virtioscsi8' => { bus => 3, addr => 9 },
            'virtioscsi9' => { bus => 3, addr => 10 },
            'virtioscsi10' => { bus => 3, addr => 11 },
            'virtioscsi11' => { bus => 3, addr => 12 },
            'virtioscsi12' => { bus => 3, addr => 13 },
            'virtioscsi13' => { bus => 3, addr => 14 },
            'virtioscsi14' => { bus => 3, addr => 15 },
            'virtioscsi15' => { bus => 3, addr => 16 },
            'virtioscsi16' => { bus => 3, addr => 17 },
            'virtioscsi17' => { bus => 3, addr => 18 },
            'virtioscsi18' => { bus => 3, addr => 19 },
            'virtioscsi19' => { bus => 3, addr => 20 },
            'virtioscsi20' => { bus => 3, addr => 21 },
            'virtioscsi21' => { bus => 3, addr => 22 },
            'virtioscsi22' => { bus => 3, addr => 23 },
            'virtioscsi23' => { bus => 3, addr => 24 },
            'virtioscsi24' => { bus => 3, addr => 25 },
            'virtioscsi25' => { bus => 3, addr => 26 },
            'virtioscsi26' => { bus => 3, addr => 27 },
            'virtioscsi27' => { bus => 3, addr => 28 },
            'virtioscsi28' => { bus => 3, addr => 29 },
            'virtioscsi29' => { bus => 3, addr => 30 },
            'virtioscsi30' => { bus => 3, addr => 31 },
        }
    } else{
        $pci_addr_map = {
            piix3 => { bus => 0, addr => 1, conflict_ok => qw(ehci)  },
            ehci => { bus => 0, addr => 1, conflict_ok => qw(piix3) }, # instead of piix3 on arm
            vga => { bus => 0, addr => 2, conflict_ok => qw(legacy-igd) },
            'legacy-igd' => { bus => 0, addr => 2, conflict_ok => qw(vga) }, # legacy-igd requires vga=none
            balloon0 => { bus => 0, addr => 3 },
            watchdog => { bus => 0, addr => 4 },
            scsihw0 => { bus => 0, addr => 5, conflict_ok => qw(pci.3) },
            'pci.3' => { bus => 0, addr => 5, conflict_ok => qw(scsihw0) }, # also used for virtio-scsi-single bridge
            scsihw1 => { bus => 0, addr => 6 },
            ahci0 => { bus => 0, addr => 7 },
            qga0 => { bus => 0, addr => 8 },
            spice => { bus => 0, addr => 9 },
            virtio0 => { bus => 0, addr => 10 },
			virtio1 => { bus => 0, addr => 11 },
            virtio2 => { bus => 0, addr => 12 },
            virtio3 => { bus => 0, addr => 13 },
            virtio4 => { bus => 0, addr => 14 },
            virtio5 => { bus => 0, addr => 15 },
            hostpci0 => { bus => 0, addr => 16 },
            hostpci1 => { bus => 0, addr => 17 },
            net0 => { bus => 0, addr => 18 },
            net1 => { bus => 0, addr => 19 },
            net2 => { bus => 0, addr => 20 },
            net3 => { bus => 0, addr => 21 },
            net4 => { bus => 0, addr => 22 },
            net5 => { bus => 0, addr => 23 },
            vga1 => { bus => 0, addr => 24 },
            vga2 => { bus => 0, addr => 25 },
            vga3 => { bus => 0, addr => 26 },
            hostpci2 => { bus => 0, addr => 27 },
            hostpci3 => { bus => 0, addr => 28 },
            #addr29 : usb-host (pve-usb.cfg)
            'pci.1' => { bus => 0, addr => 30 },
            'pci.2' => { bus => 0, addr => 31 },
            'net6' => { bus => 1, addr => 1 },
            'net7' => { bus => 1, addr => 2 },
            'net8' => { bus => 1, addr => 3 },
            'net9' => { bus => 1, addr => 4 },
            'net10' => { bus => 1, addr => 5 },
            'net11' => { bus => 1, addr => 6 },
            'net12' => { bus => 1, addr => 7 },
            'net13' => { bus => 1, addr => 8 },
            'net14' => { bus => 1, addr => 9 },
            'net15' => { bus => 1, addr => 10 },
            'net16' => { bus => 1, addr => 11 },
            'net17' => { bus => 1, addr => 12 },
            'net18' => { bus => 1, addr => 13 },
            'net19' => { bus => 1, addr => 14 },
            'net20' => { bus => 1, addr => 15 },
            'net21' => { bus => 1, addr => 16 },
            'net22' => { bus => 1, addr => 17 },
            'net23' => { bus => 1, addr => 18 },
            'net24' => { bus => 1, addr => 19 },
            'net25' => { bus => 1, addr => 20 },
            'net26' => { bus => 1, addr => 21 },
            'net27' => { bus => 1, addr => 22 },
            'net28' => { bus => 1, addr => 23 },
            'net29' => { bus => 1, addr => 24 },
            'net30' => { bus => 1, addr => 25 },
            'net31' => { bus => 1, addr => 26 },
            'xhci' => { bus => 1, addr => 27 },
            'pci.4' => { bus => 1, addr => 28 },
            'rng0' => { bus => 1, addr => 29 },
            'pci.2-igd' => { bus => 1, addr => 30 }, # replaces pci.2 in case a legacy IGD device is passed through
            'virtio6' => { bus => 2, addr => 1 },
            'virtio7' => { bus => 2, addr => 2 },
            'virtio8' => { bus => 2, addr => 3 },
            'virtio9' => { bus => 2, addr => 4 },
            'virtio10' => { bus => 2, addr => 5 },
            'virtio11' => { bus => 2, addr => 6 },
            'virtio12' => { bus => 2, addr => 7 },
            'virtio13' => { bus => 2, addr => 8 },
            'virtio14' => { bus => 2, addr => 9 },
            'virtio15' => { bus => 2, addr => 10 },
            'ivshmem' => { bus => 2, addr => 11 },
            'audio0' => { bus => 2, addr => 12 },
            'hostpci4' => { bus => 2, addr => 13 },
            'hostpci5' => { bus => 2, addr => 14 },
            'hostpci6' => { bus => 2, addr => 15 },
            'hostpci7' => { bus => 2, addr => 16 },
            'hostpci8' => { bus => 2, addr => 17 },
            'hostpci9' => { bus => 2, addr => 18 },
            'hostpci10' => { bus => 2, addr => 19 },
            'hostpci11' => { bus => 2, addr => 20 },
            'hostpci12' => { bus => 2, addr => 21 },
            'hostpci13' => { bus => 2, addr => 22 },
            'hostpci14' => { bus => 2, addr => 23 },
            'hostpci15' => { bus => 2, addr => 24 },
            'spdk0' => { bus => 2, addr => 25 },
            'spdk1' => { bus => 2, addr => 26 },
            'spdk2' => { bus => 2, addr => 27 },
            'spdk3' => { bus => 2, addr => 28 },
            'spdk4' => { bus => 2, addr => 29 },
            'spdk5' => { bus => 2, addr => 30 },
            'virtioscsi0' => { bus => 3, addr => 1 },
            'virtioscsi1' => { bus => 3, addr => 2 },
            'virtioscsi2' => { bus => 3, addr => 3 },
            'virtioscsi3' => { bus => 3, addr => 4 },
            'virtioscsi4' => { bus => 3, addr => 5 },
            'virtioscsi5' => { bus => 3, addr => 6 },
            'virtioscsi6' => { bus => 3, addr => 7 },
            'virtioscsi7' => { bus => 3, addr => 8 },
            'virtioscsi8' => { bus => 3, addr => 9 },
            'virtioscsi9' => { bus => 3, addr => 10 },
            'virtioscsi10' => { bus => 3, addr => 11 },
            'virtioscsi11' => { bus => 3, addr => 12 },
            'virtioscsi12' => { bus => 3, addr => 13 },
            'virtioscsi13' => { bus => 3, addr => 14 },
            'virtioscsi14' => { bus => 3, addr => 15 },
            'virtioscsi15' => { bus => 3, addr => 16 },
            'virtioscsi16' => { bus => 3, addr => 17 },
            'virtioscsi17' => { bus => 3, addr => 18 },
            'virtioscsi18' => { bus => 3, addr => 19 },
            'virtioscsi19' => { bus => 3, addr => 20 },
            'virtioscsi20' => { bus => 3, addr => 21 },
            'virtioscsi21' => { bus => 3, addr => 22 },
            'virtioscsi22' => { bus => 3, addr => 23 },
            'virtioscsi23' => { bus => 3, addr => 24 },
            'virtioscsi24' => { bus => 3, addr => 25 },
            'virtioscsi25' => { bus => 3, addr => 26 },
            'virtioscsi26' => { bus => 3, addr => 27 },
            'virtioscsi27' => { bus => 3, addr => 28 },
            'virtioscsi28' => { bus => 3, addr => 29 },
            'virtioscsi29' => { bus => 3, addr => 30 },
            'virtioscsi30' => { bus => 3, addr => 31 },
            'scsihw2' => { bus => 4, addr => 1 },
            'scsihw3' => { bus => 4, addr => 2 },
            'scsihw4' => { bus => 4, addr => 3 },
        }
    }
    return $pci_addr_map;
}

sub generate_mdev_uuid {
    my ($vmid, $index) = @_;
    return sprintf("%08d-0000-0000-0000-%012d", $index, $vmid);
}

my $get_addr_mapping_from_id = sub {
    my ($map, $id) = @_;

    my $d = $map->{$id};
    return if !defined($d) || !defined($d->{bus}) || !defined($d->{addr});

    return { bus => $d->{bus}, addr => sprintf("0x%x", $d->{addr}) };
};

sub print_pci_addr {
    my ($id, $bridges, $arch) = @_;

    die "$arch cannot use IDE devices\n" if $arch ne 'x86_64' && $id =~ /^ide/;

    my $res = '';

    my $map = get_pci_addr_map($arch);
    if (my $d = $get_addr_mapping_from_id->($map, $id)) {
        # Using same bus slots on all HW, so we need to check special cases here. For aarch64, the
        # virt machine has an initial pcie.0. The other pci bridges that get added are called pci.N.
        my $busname = 'pci';
        if ($arch ne 'x86_64') {
            die "aarch64/virt cannot use IDE devices\n" if $id =~ /^ide/;
            $busname = 'pcie';
        }

        $res = ",bus=$busname.$d->{bus},addr=$d->{addr}";
        $bridges->{ $d->{bus} } = 1 if $bridges;
    }

    return $res;
}

my $pcie_addr_map;

sub get_pcie_addr_map {
    $pcie_addr_map = {
        vga => { bus => 'pcie.0', addr => 1 },
        hostpci0 => { bus => "ich9-pcie-port-1", addr => 0 },
        hostpci1 => { bus => "ich9-pcie-port-2", addr => 0 },
        hostpci2 => { bus => "ich9-pcie-port-3", addr => 0 },
        hostpci3 => { bus => "ich9-pcie-port-4", addr => 0 },
        hostpci4 => { bus => "ich9-pcie-port-5", addr => 0 },
        hostpci5 => { bus => "ich9-pcie-port-6", addr => 0 },
        hostpci6 => { bus => "ich9-pcie-port-7", addr => 0 },
        hostpci7 => { bus => "ich9-pcie-port-8", addr => 0 },
        hostpci8 => { bus => "ich9-pcie-port-9", addr => 0 },
        hostpci9 => { bus => "ich9-pcie-port-10", addr => 0 },
        hostpci10 => { bus => "ich9-pcie-port-11", addr => 0 },
        hostpci11 => { bus => "ich9-pcie-port-12", addr => 0 },
        hostpci12 => { bus => "ich9-pcie-port-13", addr => 0 },
        hostpci13 => { bus => "ich9-pcie-port-14", addr => 0 },
        hostpci14 => { bus => "ich9-pcie-port-15", addr => 0 },
        hostpci15 => { bus => "ich9-pcie-port-16", addr => 0 },
        # win7 is picky about pcie assignments
        hostpci0bus0 => { bus => "pcie.0", addr => 16 },
        hostpci1bus0 => { bus => "pcie.0", addr => 17 },
        hostpci2bus0 => { bus => "pcie.0", addr => 18 },
        hostpci3bus0 => { bus => "pcie.0", addr => 19 },
        ivshmem => { bus => 'pcie.0', addr => 20 },
        hostpci4bus0 => { bus => "pcie.0", addr => 9 },
        hostpci5bus0 => { bus => "pcie.0", addr => 10 },
        hostpci6bus0 => { bus => "pcie.0", addr => 11 },
        hostpci7bus0 => { bus => "pcie.0", addr => 12 },
        hostpci8bus0 => { bus => "pcie.0", addr => 13 },
        hostpci9bus0 => { bus => "pcie.0", addr => 14 },
        hostpci10bus0 => { bus => "pcie.0", addr => 15 },
        hostpci11bus0 => { bus => "pcie.0", addr => 21 },
        hostpci12bus0 => { bus => "pcie.0", addr => 22 },
        hostpci13bus0 => { bus => "pcie.0", addr => 23 },
        hostpci14bus0 => { bus => "pcie.0", addr => 24 },
        hostpci15bus0 => { bus => "pcie.0", addr => 25 },
        }
        if !defined($pcie_addr_map);

    return $pcie_addr_map;
}


sub print_pcie_addr {
    my ($id) = @_;

    my $res = '';

    my $map = get_pcie_addr_map($id);
    if (my $d = $get_addr_mapping_from_id->($map, $id)) {
        $res = ",bus=$d->{bus},addr=$d->{addr}";
    }

    return $res;
}

# Generates the device strings for additional pcie root ports. The first 4 pcie
# root ports are defined in the pve-q35*.cfg files.
sub print_pcie_root_port {
    my ($i) = @_;
    my $res = '';

    my $root_port_addresses = {
        4 => "10.0",
        5 => "10.1",
        6 => "10.2",
        7 => "10.3",
        8 => "10.4",
        9 => "10.5",
        10 => "10.6",
        11 => "10.7",
        12 => "11.0",
        13 => "11.1",
        14 => "11.2",
        15 => "11.3",
    };

    if (defined($root_port_addresses->{$i})) {
        my $id = $i + 1;
        $res = "pcie-root-port,id=ich9-pcie-port-${id}";
        $res .= ",addr=$root_port_addresses->{$i}";
        $res .= ",x-speed=16,x-width=32,multifunction=on,bus=pcie.0";
        $res .= ",port=${id},chassis=${id}";
    }

    return $res;
}

sub print_pcie_root_port_for_port {
    my ($i) = @_;
    my $res = '';

    my $root_port_addresses = {
        0 => "0x10",# hostpci0 -> pcie.5 
        1 => "0x11",# hostpci1 -> pcie.6 
        2 => "0x12",# hostpci2 -> pcie.7 
        3 => "0x13",# hostpci3 -> pcie.8 
        4 => "0x14",# hostpci4 -> pcie.9 
        5 => "0x15",# hostpci5 -> pcie.10 
        6 => "0x16",# hostpci6 -> pcie.11 
        7 => "0x17",# hostpci7 -> pcie.12 
        8 => "0x18",# hostpci8 -> pcie.13 
        9 => "0x19",# hostpci9 -> pcie.14 
        10 => "0x1a",# hostpci10 -> pcie.15 
        11 => "0x1b",# hostpci11 -> pcie.16 
        12 => "0x1c",# hostpci12 -> pcie.17 
        13 => "0x1d",# hostpci13 -> pcie.18 
        14 => "0x1e",# hostpci14 -> pcie.19 
    };

    if (defined($root_port_addresses->{$i})) {
        my $id = $i + 5;
        $res = "pcie-root-port,id=pcie.${id}";
        $res .= ",addr=$root_port_addresses->{$i}";
        $res .= ",x-speed=16,x-width=32,multifunction=on,bus=pcie.0";
        $res .= ",port=${id},chassis=${id}";
    }

    return $res;
}

# returns the parsed pci config but parses the 'host' part into
# a list if lists into the 'id' property like this:
#
# {
#   mdev => 1,
#   rombar => ...
#   ...
#   ids => [
#       # this contains a list of alternative devices,
#       [
#           # which are itself lists of ids for one multifunction device
#           {
#               id => "0000:00:00.0",
#               vendor => "...",
#           },
#           {
#               id => "0000:00:00.1",
#               vendor => "...",
#           },
#       ],
#       [
#           ...
#       ],
#       ...
#   ],
# }
sub parse_hostpci {
    my ($value) = @_;

    return if !$value;

    my $res = PVE::JSONSchema::parse_property_string($hostpci_fmt, $value);

    my $alternatives = [];
    my $host = delete $res->{host};
    my $mapping = delete $res->{mapping};

    die "Cannot set both 'host' and 'mapping'.\n" if defined($host) && defined($mapping);

    if ($mapping) {
        # we have no ordinary pci id, must be a mapping
        my $devices = PVE::Mapping::PCI::find_on_current_node($mapping);
        die "PCI device mapping not found for '$mapping'\n" if !$devices || !scalar($devices->@*);

        my $config = PVE::Mapping::PCI::config();
        my $mapping_cfg = $config->{ids}->{$mapping};
        $res->{'live-migration-capable'} = 1 if $mapping_cfg->{'live-migration-capable'};

        for my $device ($devices->@*) {
            eval { PVE::Mapping::PCI::assert_valid($mapping, $device, $mapping_cfg) };
            die "PCI device mapping invalid (hardware probably changed): $@\n" if $@;
            push $alternatives->@*, [split(/;/, $device->{path})];
        }
    } elsif ($host) {
        push $alternatives->@*, [split(/;/, $host)];
    } else {
        die "Either 'host' or 'mapping' must be set.\n";
    }

    $res->{ids} = [];
    for my $alternative ($alternatives->@*) {
        my $ids = [];
        foreach my $id ($alternative->@*) {
            my $devs = PVE::SysFSTools::lspci($id);
            die "no PCI device found for '$id'\n" if !scalar($devs->@*);
            push $ids->@*, @$devs;
        }
        if (scalar($ids->@*) > 1) {
            $res->{'has-multifunction'} = 1;
            die "cannot use mediated device with multifunction device\n"
                if $res->{mdev} || $res->{nvidia};
        } elsif ($res->{mdev}) {
            if ($ids->[0]->{nvidia} && $res->{mdev} =~ m/^nvidia-(\d+)$/) {
                $res->{nvidia} = $1;
                delete $res->{mdev};
            }
        }
        push $res->{ids}->@*, $ids;
    }

    return $res;
}

# parses all hostpci devices from a config and does some sanity checks
# returns a hash like this:
# {
#     hostpci0 => {
#         # hash from parse_hostpci function
#     },
#     hostpci1 => { ... },
#     ...
# }
sub parse_hostpci_devices {
    my ($conf) = @_;

    my $q35 = PVE::QemuServer::Machine::machine_type_is_q35($conf);
    my $legacy_igd = 0;

    my $parsed_devices = {};
    for (my $i = 0; $i < $MAX_HOSTPCI_DEVICES; $i++) {
        my $id = "hostpci$i";
        my $d = parse_hostpci($conf->{$id});
        next if !$d;

        # check syntax
        die "q35 machine model is not enabled" if !$q35 && $d->{pcie};

        if ($d->{'legacy-igd'}) {
            die "only one device can be assigned in legacy-igd mode\n"
                if $legacy_igd;
            $legacy_igd = 1;

            die "legacy IGD assignment requires VGA mode to be 'none'\n"
                if !defined($conf->{'vga'}) || $conf->{'vga'} ne 'none';
            die "legacy IGD assignment requires rombar to be enabled\n"
                if defined($d->{rombar}) && !$d->{rombar};
            die "legacy IGD assignment is not compatible with x-vga\n"
                if $d->{'x-vga'};
            die "legacy IGD assignment is not compatible with mdev\n"
                if $d->{mdev} || $d->{nvidia};
            die "legacy IGD assignment is not compatible with q35\n"
                if $q35;
            die "legacy IGD assignment is not compatible with multifunction devices\n"
                if $d->{'has-multifunction'};
            die "legacy IGD assignment is not compatible with alternate devices\n"
                if scalar($d->{ids}->@*) > 1;
            # check first device for valid id
            die "legacy IGD assignment only works for devices on host bus 00:02.0\n"
                if $d->{ids}->[0]->[0]->{id} !~ m/02\.0$/;
        }

        $parsed_devices->{$id} = $d;
    }

    return $parsed_devices;
}

# set vgpu type of a vf of an nvidia gpu with kernel 6.8 or newer
my sub create_nvidia_device {
    my ($id, $model) = @_;

    $id = PVE::SysFSTools::normalize_pci_id($id);

    my $creation = "/sys/bus/pci/devices/$id/nvidia/current_vgpu_type";

    die "no nvidia sysfs api for '$id'\n" if !-f $creation;

    my $current = PVE::Tools::file_read_firstline($creation);
    if ($current ne "0") {
        return 1 if $current eq $model;
        # reset vgpu type so we can see all available and set the real device
        die "unable to reset vgpu type for '$id'\n" if !PVE::SysFSTools::file_write($creation, "0");
    }

    my $types = PVE::SysFSTools::get_mdev_types($id);
    my $selected;
    for my $type_definition ($types->@*) {
        next if $type_definition->{type} ne "nvidia-$model";
        $selected = $type_definition;
    }

    if (!defined($selected) || $selected->{available} < 1) {
        die "vgpu type '$model' not available for '$id'\n";
    }

    if (!PVE::SysFSTools::file_write($creation, $model)) {
        die "could not set vgpu type to '$model' for '$id'\n";
    }

    return 1;
}

# takes the hash returned by parse_hostpci_devices and for all non mdev gpus,
# selects one of the given alternatives by trying to reserve it
#
# mdev devices must be chosen later when we actually allocate it, but we
# flatten the inner list since there can only be one device per alternative anyway
sub choose_hostpci_devices {
    my ($devices, $vmid, $dry_run) = @_;

    my $used = {};

    my $add_used_device = sub {
        my ($devices) = @_;
        for my $used_device ($devices->@*) {
            my $used_id = $used_device->{id};
            die "device '$used_id' assigned more than once\n" if $used->{$used_id};
            $used->{$used_id} = 1;
        }
    };

    for (my $i = 0; $i < $MAX_HOSTPCI_DEVICES; $i++) {
        my $device = $devices->{"hostpci$i"};
        next if !$device;

        if ($device->{mdev} && !$device->{nvidia}) {
            $device->{ids} = [map { $_->[0] } $device->{ids}->@*];
            next;
        }

        if (scalar($device->{ids}->@* == 1)) {
            # we only have one alternative, use that
            $device->{ids} = $device->{ids}->[0];
            $add_used_device->($device->{ids});
            if ($device->{nvidia} && !$dry_run) {
                reserve_pci_usage($device->{ids}->[0]->{id}, $vmid, 10, undef);
                create_nvidia_device($device->{ids}->[0]->{id}, $device->{nvidia});
            }
            next;
        }

        my $found = 0;
        for my $alternative ($device->{ids}->@*) {
            my $ids = [map { $_->{id} } @$alternative];

            next if grep { defined($used->{$_}) } @$ids; # already used
            if (!$dry_run) {
                eval { reserve_pci_usage($ids, $vmid, 10, undef) };
                next if $@;
            }

            if ($device->{nvidia} && !$dry_run) {
                eval { create_nvidia_device($ids->[0], $device->{nvidia}) };
                if (my $err = $@) {
                    warn $err;
                    remove_pci_reservation($vmid, $ids);
                    next;
                }
            }

            # found one that is not used or reserved
            $add_used_device->($alternative);
            $device->{ids} = $alternative;
            $found = 1;
            last;
        }
        die "could not find a free device for 'hostpci$i'\n" if !$found;
    }

    return $devices;
}

sub print_hostpci_devices {
    my ($vmid, $conf, $devices, $vga, $winversion, $bridges, $arch, $bootorder, $dry_run) = @_;

    my $kvm_off = 0;
    my $gpu_passthrough = 0;
    my $legacy_igd = 0;

    my $pciaddr;
    my $pci_devices = choose_hostpci_devices(parse_hostpci_devices($conf), $vmid, $dry_run);

    for (my $i = 0; $i < $MAX_HOSTPCI_DEVICES; $i++) {
        my $id = "hostpci$i";
        my $d = $pci_devices->{$id};
        next if !$d;

        $legacy_igd = 1 if $d->{'legacy-igd'};

        if (my $pcie = $d->{pcie}) {
            # win7 wants to have the pcie devices directly on the pcie bus
            # instead of in the root port
            if ($winversion == 7) {
                $pciaddr = print_pcie_addr("${id}bus0");
            } else {
                # add more root ports if needed, 4 are present by default
                # by pve-q35 cfgs, rest added here on demand.
                if ($i > 3) {
                    push @$devices, '-device', print_pcie_root_port($i);
                }
                $pciaddr = print_pcie_addr($id);
            }
        } else {
            # other arch need pcie-root-port too! We try add it
            if ($arch ne 'x86_64') {
                push @$devices, '-device', print_pcie_root_port_for_port($i);
            }
            my $pci_name = $d->{'legacy-igd'} ? 'legacy-igd' : $id;
            $pciaddr = print_pci_addr($pci_name, $bridges, $arch);
        }

        my $num_devices = scalar($d->{ids}->@*);
        my $multifunction = $num_devices > 1 && !$d->{mdev};

        my $xvga = '';
        if ($d->{'x-vga'}) {
            $xvga = ',x-vga=on' if !($conf->{bios} && $conf->{bios} eq 'ovmf');
            $kvm_off = 1;
            $vga->{type} = 'none' if !defined($conf->{vga});
            $gpu_passthrough = 1;
        }

        my $sysfspath;
        if ($d->{mdev}) {
            my $uuid = $conf->{uuid} // generate_mdev_uuid($vmid, $i);
            $sysfspath = "/sys/bus/mdev/devices/$uuid";
        }

        for (my $j = 0; $j < $num_devices; $j++) {
            my $pcidevice = $d->{ids}->[$j];
            my $devicestr = "vfio-pci";

            if ($sysfspath) {
                $devicestr .= ",sysfsdev=$sysfspath";
            } else {
                $devicestr .= ",host=$pcidevice->{id}";
            }

            if ($d->{'live-migration-capable'}) {
                $devicestr .= ",enable-migration=on";
            }

            my $mf_addr = $multifunction ? ".$j" : '';
            $devicestr .= ",id=${id}${mf_addr}${pciaddr}${mf_addr}";

            my $mdevtype = $d->{mdev} // undef;
            if (defined($mdevtype) && $mdevtype =~ /^(.*?)-/) {
                $mdevtype = $1;
            }

            if ($j == 0) {
                $devicestr .= ',rombar=0' if defined($d->{rombar}) && !$d->{rombar};
                $devicestr .= "$xvga";
                $devicestr .= ",multifunction=on" if $multifunction;
                $devicestr .= ",romfile=/usr/share/kvm/$d->{romfile}" if $d->{romfile};
                $devicestr .= ",bootindex=$bootorder->{$id}" if $bootorder->{$id};
                for my $option (qw(vendor-id device-id sub-vendor-id sub-device-id)) {
                    $devicestr .= ",x-pci-$option=$d->{$option}" if $d->{$option};
                }
            }
            if ($mdevtype && $vga->{type} eq 'mdev'){
                $devicestr .= ",display=on";
                if ($mdevtype eq "i915"){
                    $devicestr .= ",x-igd-opregion=on" ;
                }
                $devicestr .= ",ramfb=on" if $d->{ramfb};
                $devicestr .= ",driver=vfio-pci-nohotplug";
            }

            push @$devices, '-device', $devicestr;
            last if $d->{mdev};
        }
    }

    return ($kvm_off, $gpu_passthrough, $legacy_igd, $pci_devices);
}

sub prepare_pci_device {
    my ($vmid, $pciid, $index, $device) = @_;

    my $conf = PVE::QemuConfig->load_config($vmid);
    my $info = PVE::SysFSTools::pci_device_info("$pciid");
    die "cannot prepare PCI pass-through, IOMMU not present\n"
        if !PVE::SysFSTools::check_iommu_support();
    die "no pci device info for device '$pciid'\n" if !$info;

    if ($device->{mac}){
        my $mac = $device->{mac};
        my $vlan = $device->{tag};
        pci_set_sriov_device($pciid,$mac,$vlan);
    }

    if ($device->{nvidia}) {
        # nothing to do
    } elsif (my $mdev = $device->{mdev}) {
        my $uuid = $conf->{uuid} // generate_mdev_uuid($vmid, $index);
        PVE::SysFSTools::pci_create_mdev_device($pciid, $uuid, $mdev);
    } else {
        die "can't unbind/bind PCI group to VFIO '$pciid'\n"
            if !PVE::SysFSTools::pci_dev_group_bind_to_vfio($pciid);
        warn
            "failed to reset PCI device '$pciid', but trying to continue as not all devices need a reset\n"
            if $info->{has_fl_reset} && !PVE::SysFSTools::pci_dev_reset($info);
    }

    return $info;
}

my $RUNDIR = '/run/qemu-server';
my $PCIID_RESERVATION_FILE = "${RUNDIR}/pci-id-reservations";
my $PCIID_RESERVATION_LOCK = "${PCIID_RESERVATION_FILE}.lock";

# a list of PCI ID to VMID reservations, the validity is protected against leakage by either a PID,
# for successfully started VM processes, or a expiration time for the initial time window between
# reservation and actual VM process start-up.
my $parse_pci_reservation_unlocked = sub {
    my $pci_ids = {};
    if (my $fh = IO::File->new($PCIID_RESERVATION_FILE, "r")) {
        while (my $line = <$fh>) {
            if ($line =~ m/^($PCIRE)\s(\d+)\s(time|pid)\:(\d+)$/) {
                $pci_ids->{$1} = {
                    vmid => $2,
                    "$3" => $4,
                };
            }
        }
    }
    return $pci_ids;
};

my $write_pci_reservation_unlocked = sub {
    my ($reservations) = @_;

    my $data = "";
    for my $pci_id (sort keys $reservations->%*) {
        my ($vmid, $pid, $time) = $reservations->{$pci_id}->@{ 'vmid', 'pid', 'time' };
        if (defined($pid)) {
            $data .= "$pci_id $vmid pid:$pid\n";
        } else {
            $data .= "$pci_id $vmid time:$time\n";
        }
    }
    PVE::Tools::file_set_contents($PCIID_RESERVATION_FILE, $data);
};

# removes all PCI device reservations held by the `vmid`
sub remove_pci_reservation {
    my ($vmid, $pci_ids) = @_;

    PVE::Tools::lock_file(
        $PCIID_RESERVATION_LOCK,
        2,
        sub {
            my $reservation_list = $parse_pci_reservation_unlocked->();
            for my $id (keys %$reservation_list) {
                next if defined($pci_ids) && !grep { $_ eq $id } $pci_ids->@*;
                my $reservation = $reservation_list->{$id};
                next if $reservation->{vmid} != $vmid;
                delete $reservation_list->{$id};
            }
            $write_pci_reservation_unlocked->($reservation_list);
        },
    );
    die $@ if $@;
}

# return all currently reserved ids from the given vmid
sub get_reservations {
    my ($vmid) = @_;

    my $reservations = $parse_pci_reservation_unlocked->();

    my $list = [];

    for my $pci_id (sort keys $reservations->%*) {
        push $list->@*, $pci_id if $reservations->{$pci_id}->{vmid} == $vmid;
    }

    return $list;
}

sub reserve_pci_usage {
    my ($requested_ids, $vmid, $timeout, $pid) = @_;

    $requested_ids = [$requested_ids] if !ref($requested_ids);
    return if !scalar(@$requested_ids); # do nothing for empty list

    PVE::Tools::lock_file(
        $PCIID_RESERVATION_LOCK,
        5,
        sub {
            my $reservation_list = $parse_pci_reservation_unlocked->();

            my $ctime = time();
            for my $id ($requested_ids->@*) {
                my $reservation = $reservation_list->{$id};
                if ($reservation && $reservation->{vmid} != $vmid) {
                    # check time based reservation
                    die
                        "PCI device '$id' is currently reserved for use by VMID '$reservation->{vmid}'\n"
                        if defined($reservation->{time}) && $reservation->{time} > $ctime;

                    if (my $reserved_pid = $reservation->{pid}) {
                        # check running vm
                        my $running_pid =
                            PVE::QemuServer::Helpers::vm_running_locally($reservation->{vmid});
                        if (defined($running_pid) && $running_pid == $reserved_pid) {
                            die
                                "PCI device '$id' already in use by VMID '$reservation->{vmid}'\n";
                        } else {
                            warn "leftover PCI reservation found for $id, lets take it...\n";
                        }
                    }
                } elsif ($reservation) {
                    # already reserved by the same vmid
                    if (my $reserved_time = $reservation->{time}) {
                        if (defined($timeout)) {
                            # use the longer timeout
                            my $old_timeout = $reservation->{time} - 5 - $ctime;
                            $timeout = $old_timeout if $old_timeout > $timeout;
                        }
                    } elsif (my $reserved_pid = $reservation->{pid}) {
                        my $running_pid =
                            PVE::QemuServer::Helpers::vm_running_locally($reservation->{vmid});
                        if (defined($running_pid) && $running_pid == $reservation->{pid}) {
                            if (defined($pid)) {
                                die
                                    "PCI device '$id' already in use by running VMID '$reservation->{vmid}'\n";
                            } elsif (defined($timeout)) {
                                # ignore timeout reservation for running vms, can happen with e.g.
                                # qm showcmd
                                return;
                            }
                        }
                    }
                }

                $reservation_list->{$id} = { vmid => $vmid };
                if (defined($pid)) { # VM started up, we can reserve now with the actual PID
                    $reservation_list->{$id}->{pid} = $pid;
                } elsif (defined($timeout)) { # temporary reserve as we don't now the PID yet
                    $reservation_list->{$id}->{time} = $ctime + $timeout + 5;
                }
            }
            $write_pci_reservation_unlocked->($reservation_list);
        },
    );
    die $@ if $@;
}

sub pci_set_sriov_device {
    my ($pciid,$mac,$vlan) = @_;
    if (! -d "/sys/bus/pci/devices/$pciid/physfn") {
        return
    }

    my $regex = qr/^virtfn(\d+)$/;
    my $pfpath = "/sys/bus/pci/devices/$pciid/physfn";
    dir_glob_foreach($pfpath,$regex,sub {
        my ($name) = @_;
        my $vfpath = "$pfpath/$name";
        my $pciid2 = basename(realpath($vfpath));
        return if $pciid2 ne $pciid;
        if ($name =~ $regex) {
            my $vf_num = $1;
            my $regex2 = qr/(?:eth\d+|en[^:.]+|ib[^:.]+)/;
            dir_glob_foreach("$pfpath/net",$regex2,sub {
                my ($pfname) = @_;
                $vlan = 0 if !$vlan;
                my $cmd = [
                    'ip',
                    'link',
                    'set',
                    $pfname,
                    'vf',
                    $vf_num,
                    'mac',
                    $mac,
                    'trust',
                    'on',
                    'spoofchk',
                    'off',
                    'vlan',
                    $vlan
                ];
                my $rc = PVE::Tools::run_command($cmd, noerr => 1, quiet => 0);
                warn "$rc" if $rc;
            }
        )
    } else {
        return
    }
    }
)
}

1;
