package PVE::QemuServer::Spdk;

use strict;
use warnings;

use Fcntl qw(F_GETFD F_SETFD FD_CLOEXEC);
use IO::Socket::UNIX;
use POSIX;
use Socket qw(SOCK_STREAM);

use PVE::JSONSchema qw(parse_property_string);
use PVE::Mapping::Dir;
use PVE::QemuServer::Helpers;
use PVE::RESTEnvironment qw(log_warn);
use PVE::QemuServer::Drive qw(parse_drive max_spdk_disks);
use PVE::Storage;
use PVE::QemuServer::PCI qw(print_pci_addr);
use PVE::Tools qw(get_host_arch);

use base qw(Exporter);

our @EXPORT_OK = qw(
max_spdk
start_all_spdk
spdk_enabled
add_spdk_char
get_cpu_mask
);

my $MAX_SPDK_DISKS = max_spdk_disks();
my $spdk_bin = '/usr/bin/spdk_rpc';


sub add_spdk_char {
	my ($conf, $vmid, $devices) = @_;
    my $arch = $conf->{arch} || get_host_arch();
    my $machine_type = $conf->{machine} ;
    if (!$machine_type) {
        if ($arch eq 'x86_64') {
            $machine_type = 'pc';
        } else {
            $machine_type = 'virt';
        }
    }

    # for (my $i = 0; $i < $MAX_SPDK_DISKS; $i++) {
	# 	my $opt = "spdk$i";
	# 	next if !$conf->{$opt};
	# 	push @$devices, '-chardev', "socket,id=spdk_vhost_blk$i,path=/var/tmp/vm-$vmid-spdk$i";
    #     my $pciaddr = print_pci_addr("$opt", undef, $arch, $machine_type);
	# 	push @$devices, '-device', "vhost-user-blk-pci,chardev=spdk_vhost_blk$i$pciaddr,num-queues=4";
    # }

    my $bootorder = PVE::QemuServer::device_bootorder($conf);
    for (my $i = 0; $i < $MAX_SPDK_DISKS; $i++) {
		my $opt = "spdk$i";
		next if !$conf->{$opt};
        my $drive = parse_drive($opt, $conf->{$opt});
        $drive->{bootindex} = $bootorder->{$opt} if $bootorder->{$opt};
		push @$devices, '-chardev', "socket,id=spdk_vhost_scsi_$i,path=/var/tmp/vm-$vmid-$opt";
        my $pciaddr = print_pci_addr("$opt", undef, $arch, $machine_type);
        my $drive_cmd ="vhost-user-scsi-pci,chardev=spdk_vhost_scsi_$i$pciaddr";
        if ($drive->{bootindex}) {
            $drive_cmd .= ",bootindex=$drive->{bootindex}";
        }
        if ($drive->{queues}) {
            $drive_cmd .= ",num_queues=$drive->{queues}";
        } else {
            $drive_cmd .= ",num_queues=4";
        }
        
		push @$devices, '-device', $drive_cmd;
    }
}

sub start_all_spdk {
    my ($conf, $vmid) = @_;
    for (my $i = 0; $i < $MAX_SPDK_DISKS; $i++) {
	    my $opt = "spdk$i";
        next if !$conf->{$opt};

       # my $spdk = parse_property_string('pve-qm-spdk', $conf->{$opt});
       start_spdk($vmid, $opt);
    }
}

sub start_spdk {
    my ($vmid, $opt) = @_;
    my $storecfg = PVE::Storage::config();
    my $conf = PVE::QemuConfig->load_config($vmid);

    my $cpu_mask = undef;
    $cpu_mask = get_cpu_mask($conf->{affinity}) if $conf->{affinity};

    my $drive = parse_drive($opt, $conf->{$opt});
    my ($path, $format) = PVE::QemuServer::Drive::get_path_and_format($storecfg, $vmid,$drive);
    my ($storeid, $volname) = PVE::Storage::parse_volume_id($drive->{file}, 1);
    my $scfg = PVE::Storage::storage_config($storecfg, $storeid);

    delete_vhost_controller("vm-$vmid-$opt");
    if ($scfg->{type} eq 'rbd') {
        my $rbd_name = $volname;
        if ($volname =~ m|/|) {
            ($rbd_name) = $volname =~ m|.*/(.+)$|;
        }
        delete_rbd_bdev("vm-disk-$vmid-$opt");
        create_rbd_bdev("vm-disk-$vmid-$opt", $scfg->{pool}, $rbd_name, 4096);
    } else {
        delete_aio_bdev("vm-disk-$vmid-$opt");
        create_aio_bdev($path,"vm-disk-$vmid-$opt", 4096);
    }
    create_vhost_scsi_controller("vm-$vmid-$opt", $cpu_mask);
    create_vhost_scsi_lun("vm-$vmid-$opt", "vm-disk-$vmid-$opt");
}
sub spdk_enabled {
    my ($conf) = @_;    my $spdk_enabled = 0;
    for (my $i = 0; $i < $MAX_SPDK_DISKS; $i++) {
        my $opt = "spdk$i";
        next if !$conf->{$opt};
        $spdk_enabled = 1;
    }
    return $spdk_enabled;
}

sub check_bdev {
    my ($name) = @_;
		my $has_aio_bdev = 0;
		my $cmd = [$spdk_bin, "bdev_get_bdevs","-b","$name"];
		my $rc = PVE::Tools::run_command($cmd, noerr => 1, quiet => 1);
		if ($rc == 0) {
			$has_aio_bdev = 1;
		}
		return $has_aio_bdev;
}

sub check_vhost_controller {
    my ($name) = @_;
		my $has_vhost_controller = 0;
		my $cmd = [$spdk_bin, "vhost_get_controllers","--name","$name"];
		my $rc = PVE::Tools::run_command($cmd, noerr => 1, quiet => 1);
		if ($rc == 0) {
			$has_vhost_controller = 1;
		}
		return $has_vhost_controller;
}

sub delete_aio_bdev {
    my ($name) = @_;
		if (!check_bdev($name)) {
			return;
		}
    my $cmd = [$spdk_bin, "bdev_aio_delete", "$name"];
    my $rc = PVE::Tools::run_command($cmd, noerr => 1, quiet => 1);
    warn "$rc" if $rc;
}

sub delete_vhost_controller {
    my ($name) = @_;
		if (!check_vhost_controller($name)) {
			return;
		}
    my $cmd = [$spdk_bin, "vhost_delete_controller", "$name"];
    my $rc = PVE::Tools::run_command($cmd, noerr => 1, quiet => 1);
    warn "$rc" if $rc;
}

sub create_aio_bdev {
    my ($name, $path, $block_size) = @_;
    my $cmd = [$spdk_bin, "bdev_aio_create","$name", "$path",  "$block_size"];
    my $rc = PVE::Tools::run_command($cmd, noerr => 1, quiet => 1);
    warn "$rc" if $rc;
}

sub create_vhost_controller {
    my ($name, $path, $cpus) = @_;
    my $cmd = [$spdk_bin, "vhost_create_blk_controller", "$name", "$path"];
    if ($cpus) {
       push @$cmd, "--cpumask", "$cpus";
    }
    my $rc = PVE::Tools::run_command($cmd, noerr => 1, quiet => 1);
    warn "$rc" if $rc;
}

sub create_vhost_scsi_controller {
    my ($name, $cpus) = @_;
    my $cmd = [$spdk_bin, "vhost_create_scsi_controller", "$name"];
    if ($cpus) {
       push @$cmd, "--cpumask", "$cpus";
    }
    my $rc = PVE::Tools::run_command($cmd, noerr => 1, quiet => 0);
    die "$rc" if $rc;
}

sub create_vhost_scsi_lun {
    my ($name, $path) = @_;
    my $cmd = [$spdk_bin, "vhost_scsi_controller_add_target", "$name", 0,"$path"];
    my $rc = PVE::Tools::run_command($cmd, noerr => 1, quiet => 0);
    die "$rc" if $rc;
}

sub create_rbd_bdev {
    my ($name, $pool_name, $rbd_name, $block_size) = @_;
    my $cmd = [$spdk_bin, "bdev_rbd_create", "-b", "$name",  "$pool_name","$rbd_name", "$block_size"];
    my $rc = PVE::Tools::run_command($cmd, noerr => 1, quiet => 0);
    die "$rc" if $rc;
}

sub delete_rbd_bdev {
    my ($name) = @_;
    my $cmd = [$spdk_bin, "bdev_rbd_delete", "$name"];
    return if !check_bdev($name);
    print "delete_rbd_bdev($name)\n";
    my $rc = PVE::Tools::run_command($cmd, noerr => 1, quiet => 1);
    warn "$rc" if $rc;
}

sub stop_all_spdk {
  my ($vmid) = @_;
  my $conf = PVE::QemuConfig->load_config($vmid);
  for (my $i = 0; $i < $MAX_SPDK_DISKS; $i++) {
	  my $opt = "spdk$i";
      next if !$conf->{$opt};
      stop_spdk($vmid, $opt);
  }
}
sub stop_spdk {
    my ($vmid, $opt) = @_;
    my $storecfg = PVE::Storage::config();
    my $conf = PVE::QemuConfig->load_config($vmid);


    my $drive = parse_drive($opt, $conf->{$opt});
    my ($storeid, $volname) = PVE::Storage::parse_volume_id($drive->{file}, 1);
    my $scfg = PVE::Storage::storage_config($storecfg, $storeid);

    delete_vhost_controller("vm-$vmid-$opt");
    if ($scfg->{type} eq 'rbd') {
        delete_rbd_bdev("vm-disk-$vmid-$opt");
    } else {
        delete_aio_bdev("vm-disk-$vmid-$opt");
    }
    delete_vhost_controller("vm-$vmid-$opt");
}

sub get_cpu_mask {
    my ($cpu_list) = @_;
    return "0x1" if !defined($cpu_list) || $cpu_list eq '';

    my @cpus = ();
    for my $part (split /,/, $cpu_list) {
        $part =~ s/^\s+|\s+$//g;
        if ($part =~ /^(\d+)-(\d+)$/) {
            my ($start, $end) = ($1, $2);
            push @cpus, ($start..$end);
        } elsif ($part =~ /^\d+$/) {
            push @cpus, $part;
        } else {
            die "Invalid CPU specification: $part\n";
        }
    }

    my %seen = ();
    @cpus = sort { $a <=> $b } grep { !$seen{$_}++ } @cpus;
    my $mask = 0;
    for my $cpu (@cpus) {
        $mask |= (1 << $cpu);
    }
    return sprintf("0x%x", $mask);
}

1;