package PVE::QemuServer::Autoinstall;

# Generate unattended installation files (Windows autounattend.xml, kickstart,
# Ubuntu autoinstall) and put them on the cloud-init drive, so that an
# installer booted from an install ISO picks them up automatically.

use strict;
use warnings;

use Digest::SHA;
use MIME::Base64 qw(encode_base64);
use URI::Escape;

use PVE::JSONSchema;
use PVE::Storage;
use PVE::Tools;
use PVE::QemuServer::Drive;
use PVE::QemuServer::Helpers;
use PVE::QemuServer::Timezone;

# NOTE: PVE::QemuServer and PVE::QemuServer::Cloudinit use this module, so only
# call into them with fully qualified names at runtime.

# provided by the pxvirt-virtio-win package
our $VIRTIO_WIN_DIR = '/usr/share/pve-manager/virtio-win';
my $VIRTIO_WIN_DRIVERS = [qw(viostor vioscsi NetKVM Balloon vioserial)];
my $QEMU_GA_MSI = {
    x86_64 => 'guest-agent/qemu-ga-x86_64.msi',
    aarch64 => 'guest-agent/qemu-ga-arm64.msi',
};

my $SPECIALIZE_SCRIPT = '/autoinstall/specialize.cmd';
my $SPECIALIZE_COMMAND = 'cmd.exe /c for %d in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do'
    . ' if exist %d:\\autoinstall\\specialize.cmd %d:\\autoinstall\\specialize.cmd';

my $installer_types = {
    windows => {
        file => '/autounattend.xml',
        # Windows Setup scans the root of all removable media
        label => 'AUTOUNATTEND',
        joliet => 1,
    },
    kickstart => {
        file => '/ks.cfg',
        # Anaconda loads /ks.cfg from a volume labeled OEMDRV automatically
        label => 'OEMDRV',
    },
    ubuntu => {
        file => '/user-data',
        # subiquity reads the NoCloud data source
        label => 'CIDATA',
    },
};

sub parse_autoinstall {
    my ($conf) = @_;

    my $value = $conf->{autoinstall};
    return if !defined($value);
    return PVE::JSONSchema::parse_property_string('pve-qm-autoinstall', $value);
}

sub is_enabled {
    my ($conf) = @_;

    my $ai = parse_autoinstall($conf);
    return $ai && $ai->{enabled} ? 1 : 0;
}

sub get_type {
    my ($conf, $ai) = @_;

    return $ai->{type} if $ai->{type};
    return 'windows' if PVE::QemuServer::Helpers::windows_version($conf->{ostype});
    return 'kickstart';
}

my sub is_hashed_password {
    my ($password) = @_;
    return $password =~ m/^\$(?:[156]|2[ay])(\$.+){2}/;
}

my sub get_sshkeys {
    my ($conf) = @_;

    return [] if !defined($conf->{sshkeys});
    my $keys = URI::Escape::uri_unescape($conf->{sshkeys});
    return [grep { /\S/ } map { s/^\s+|\s+$//gr } split(/\n/, $keys)];
}

my sub yaml_quote {
    my ($value) = @_;
    $value =~ s/'/''/g;
    return "'$value'";
}

my sub xml_escape {
    my ($value) = @_;
    $value =~ s/&/&amp;/g;
    $value =~ s/</&lt;/g;
    $value =~ s/>/&gt;/g;
    $value =~ s/"/&quot;/g;
    $value =~ s/'/&apos;/g;
    return $value;
}

my sub ks_quote {
    my ($value) = @_;
    $value =~ s/'/'"'"'/g;
    return "'$value'";
}

my sub prefix_to_netmask {
    my ($prefix) = @_;
    my $mask = $prefix == 0 ? 0 : (0xffffffff << (32 - $prefix)) & 0xffffffff;
    return join('.', unpack('C4', pack('N', $mask)));
}

# Collect the network configuration of all interfaces that have an ipconfig.
sub get_network_config {
    my ($conf) = @_;

    my $res = [];
    my @ifaces = grep { /^net\d+$/ } keys %$conf;
    for my $iface (sort { ($a =~ s/^net//r) <=> ($b =~ s/^net//r) } @ifaces) {
        my ($id) = $iface =~ m/^net(\d+)$/;
        next if !$conf->{"ipconfig$id"};

        my $net = PVE::QemuServer::parse_net($conf->{$iface});
        my $ipconfig = PVE::QemuServer::parse_ipconfig($conf->{"ipconfig$id"});

        my $entry = {
            id => $id,
            mac => lc($net->{macaddr} // ''),
        };

        if (defined(my $ip = $ipconfig->{ip})) {
            if ($ip eq 'dhcp') {
                $entry->{dhcp4} = 1;
            } else {
                my ($addr, $prefix) = split('/', $ip);
                $entry->{ip} = $addr;
                $entry->{prefix} = $prefix;
                $entry->{netmask} = prefix_to_netmask($prefix);
                $entry->{gw} = $ipconfig->{gw};
            }
        }
        if (defined(my $ip6 = $ipconfig->{ip6})) {
            if ($ip6 eq 'dhcp' || $ip6 eq 'auto') {
                $entry->{ip6mode} = $ip6;
            } else {
                my ($addr, $prefix) = split('/', $ip6);
                $entry->{ip6} = $addr;
                $entry->{prefix6} = $prefix;
                $entry->{gw6} = $ipconfig->{gw6};
            }
        }

        push @$res, $entry;
    }

    return $res;
}

# Best effort guess of the device name the guest kernel assigns to the boot disk.
sub get_target_disk {
    my ($conf, $type) = @_;

    return '0' if $type eq 'windows';

    my @disks;
    for my $ds (PVE::QemuServer::Drive::valid_drive_names_for_boot()) {
        next if !$conf->{$ds};
        my $drive = PVE::QemuServer::Drive::parse_drive($ds, $conf->{$ds});
        next if !$drive;
        next if PVE::QemuServer::Drive::drive_is_cdrom($drive, 1);
        next if PVE::QemuServer::Drive::drive_is_cloudinit($drive);
        push @disks, $ds;
    }
    return if !@disks;

    my $bootdisk;
    my %is_disk = map { $_ => 1 } @disks;
    for my $ds (PVE::QemuServer::Drive::get_bootdisks($conf)->@*) {
        if ($is_disk{$ds}) {
            $bootdisk = $ds;
            last;
        }
    }
    $bootdisk //= $disks[0];

    my ($bus) = $bootdisk =~ m/^([a-z]+)\d+$/;
    # @disks is in controller order, which is close to the probing order in the guest
    my $rank_on = sub {
        my ($re) = @_;
        my @same = grep { $_ =~ $re } @disks;
        for (my $i = 0; $i < @same; $i++) {
            return $i if $same[$i] eq $bootdisk;
        }
        return 0;
    };

    if ($bus eq 'virtio') {
        return 'vd' . chr(ord('a') + $rank_on->(qr/^virtio\d+$/));
    } elsif ($bus eq 'nvme') {
        return 'nvme' . $rank_on->(qr/^nvme\d+$/) . 'n1';
    } elsif ($bus eq 'ide' || $bus eq 'sata' || $bus eq 'scsi') {
        return 'sd' . chr(ord('a') + $rank_on->(qr/^(?:sata|scsi|ide)\d+$/));
    }

    return;
}

sub get_host_timezone {
    if (-f '/etc/timezone') {
        my $tz = PVE::Tools::file_read_firstline('/etc/timezone');
        return $tz if defined($tz) && $tz =~ m|^[A-Za-z0-9_/+-]+$|;
    }
    if (my $link = readlink('/etc/localtime')) {
        return $1 if $link =~ m|zoneinfo/([A-Za-z0-9_/+-]+)$|;
    }
    return 'UTC';
}

sub get_domain_settings {
    my ($conf) = @_;

    my $name = $conf->{cidomain} or return;
    die "autoinstall: joining domain '$name' requires cidomainuser and cidomainpassword\n"
        if !defined($conf->{cidomainuser}) || !defined($conf->{cidomainpassword});

    return {
        name => $name,
        user => $conf->{cidomainuser},
        password => $conf->{cidomainpassword},
        ou => $conf->{cidomainou},
    };
}

sub get_settings {
    my ($conf, $vmid, $ai, $type) = @_;

    my ($hostname, $fqdn) = PVE::QemuServer::Cloudinit::get_hostname_fqdn($conf, $vmid);
    my ($searchdomains, $nameservers) = PVE::QemuServer::Cloudinit::get_dns_conf($conf);

    my $password = $conf->{cipassword};
    my $password_hash;
    if (defined($password)) {
        $password_hash =
            is_hashed_password($password) ? $password : PVE::Tools::encrypt_pw($password);
    }

    # Linux guests use the time zone of the host, Windows keeps its default
    my $timezone = $ai->{timezone} // get_host_timezone();
    my ($keyboard, $input_locale) = PVE::QemuServer::Timezone::keyboard_layout($timezone)->@*;

    return {
        vmid => $vmid,
        hostname => $hostname,
        fqdn => $fqdn,
        username => $conf->{ciuser},
        password => $password,
        password_hash => $password_hash,
        sshkeys => get_sshkeys($conf),
        nameservers => $nameservers // [],
        searchdomains => $searchdomains // [],
        networks => get_network_config($conf),
        disk => get_target_disk($conf, $type),
        timezone => $timezone,
        keyboard => $keyboard,
        input_locale => $input_locale,
        productkey => $ai->{productkey},
        rdp => $ai->{rdp} ? 1 : 0,
        domain => scalar(get_domain_settings($conf)),
        edition => $ai->{edition},
        arch => PVE::QemuServer::Helpers::get_vm_arch($conf),
        uefi => ($conf->{bios} // '') eq 'ovmf' ? 1 : 0,
        winversion => PVE::QemuServer::Helpers::windows_version($conf->{ostype}),
        tpm => $conf->{tpmstate0} ? 1 : 0,
    };
}

# Variables available as {{name}} in user provided installation files.
sub get_template_variables {
    my ($settings) = @_;

    my $vars = {
        vmid => $settings->{vmid},
        hostname => $settings->{hostname},
        fqdn => $settings->{fqdn},
        username => $settings->{username} // '',
        password => $settings->{password} // '',
        password_hash => $settings->{password_hash} // '',
        sshkeys => join("\n", $settings->{sshkeys}->@*),
        sshkey => $settings->{sshkeys}->[0] // '',
        nameserver => join(' ', $settings->{nameservers}->@*),
        searchdomain => join(' ', $settings->{searchdomains}->@*),
        disk => $settings->{disk} // '',
        timezone => $settings->{timezone} // '',
        keyboard => $settings->{keyboard} // '',
        productkey => $settings->{productkey} // '',
        edition => $settings->{edition} // '',
    };

    for my $net ($settings->{networks}->@*) {
        my $p = "net$net->{id}";
        $vars->{"${p}_mac"} = $net->{mac};
        $vars->{"${p}_ip"} = $net->{dhcp4} ? 'dhcp' : $net->{ip} // '';
        $vars->{"${p}_prefix"} = $net->{prefix} // '';
        $vars->{"${p}_netmask"} = $net->{netmask} // '';
        $vars->{"${p}_gw"} = $net->{gw} // '';
        $vars->{"${p}_ip6"} = $net->{ip6mode} // $net->{ip6} // '';
        $vars->{"${p}_prefix6"} = $net->{prefix6} // '';
        $vars->{"${p}_gw6"} = $net->{gw6} // '';
    }

    # shortcuts for the first configured interface
    if (my $first = $settings->{networks}->[0]) {
        my $p = "net$first->{id}";
        $vars->{$_} = $vars->{"${p}_$_"} for qw(mac ip prefix netmask gw ip6 prefix6 gw6);
    }

    return $vars;
}

sub render_template {
    my ($content, $vars) = @_;

    $content =~ s/\{\{\s*([A-Za-z0-9_]+)\s*\}\}/exists($vars->{$1}) ? $vars->{$1} : $&/ge;
    return $content;
}

sub generate_kickstart {
    my ($s) = @_;

    my $ks = "text\n";
    $ks .= "eula --agreed\n";
    $ks .= "lang en_US.UTF-8\n";
    $ks .= "keyboard --xlayouts='$s->{keyboard}'\n";
    $ks .= "timezone $s->{timezone} --utc\n";
    $ks .= "firstboot --disable\n";
    $ks .= "skipx\n";

    my $nameservers = join(',', $s->{nameservers}->@*);
    for my $net ($s->{networks}->@*) {
        my $line = "network --device=$net->{mac} --onboot=yes --activate";
        if ($net->{dhcp4}) {
            $line .= " --bootproto=dhcp";
        } elsif ($net->{ip}) {
            $line .= " --bootproto=static --ip=$net->{ip} --netmask=$net->{netmask}";
            $line .= " --gateway=$net->{gw}" if $net->{gw};
            $line .= " --nameserver=$nameservers" if $nameservers;
        } else {
            $line .= " --noipv4";
        }
        if (my $mode = $net->{ip6mode}) {
            $line .= " --ipv6=$mode";
        } elsif ($net->{ip6}) {
            $line .= " --ipv6=$net->{ip6}/$net->{prefix6}";
            $line .= " --ipv6gateway=$net->{gw6}" if $net->{gw6};
        }
        $ks .= "$line\n";
    }
    $ks .= "network --hostname=$s->{fqdn}\n";

    my $username = $s->{username};
    my ($pwflag, $pw);
    if (defined($s->{password})) {
        $pwflag = is_hashed_password($s->{password}) ? '--iscrypted' : '--plaintext';
        $pw = ks_quote($s->{password});
    }

    if (!defined($username) || $username eq 'root') {
        $username = 'root';
        if (defined($pw)) {
            $ks .= "rootpw $pwflag $pw\n";
        } else {
            $ks .= "rootpw --lock\n";
        }
    } else {
        $ks .= "rootpw --lock\n";
        my $line = "user --name=$username --groups=wheel";
        $line .= " $pwflag --password=$pw" if defined($pw);
        $ks .= "$line\n";
    }
    for my $key ($s->{sshkeys}->@*) {
        $key =~ s/"/\\"/g;
        $ks .= "sshkey --username=$username \"$key\"\n";
    }

    if (my $disk = $s->{disk}) {
        $ks .= "ignoredisk --only-use=$disk\n";
        $ks .= "zerombr\n";
        $ks .= "clearpart --all --initlabel --drives=$disk\n";
        $ks .= "bootloader --boot-drive=$disk\n";
    } else {
        $ks .= "zerombr\n";
        $ks .= "clearpart --all --initlabel\n";
    }
    $ks .= "autopart --type=lvm\n";
    $ks .= "services --enabled=sshd,qemu-guest-agent\n";
    # eject the installation media, so the guest boots from disk afterwards
    $ks .= "reboot --eject\n";
    $ks .= "\n%packages\n\@core\nqemu-guest-agent\n%end\n";

    return $ks;
}

sub generate_ubuntu {
    my ($s) = @_;

    die "autoinstall: ubuntu requires a password (cipassword)\n"
        if !defined($s->{password_hash});

    my $username = $s->{username} // 'ubuntu';

    my $y = "#cloud-config\n";
    $y .= "autoinstall:\n";
    $y .= "  version: 1\n";
    $y .= "  locale: 'en_US.UTF-8'\n";
    $y .= "  keyboard:\n";
    $y .= "    layout: " . yaml_quote($s->{keyboard}) . "\n";
    $y .= "  timezone: " . yaml_quote($s->{timezone}) . "\n";
    $y .= "  identity:\n";
    $y .= "    hostname: " . yaml_quote($s->{hostname}) . "\n";
    $y .= "    username: " . yaml_quote($username) . "\n";
    $y .= "    password: " . yaml_quote($s->{password_hash}) . "\n";
    $y .= "  ssh:\n";
    $y .= "    install-server: true\n";
    $y .= "    allow-pw: " . ($s->{sshkeys}->@* ? 'false' : 'true') . "\n";
    if ($s->{sshkeys}->@*) {
        $y .= "    authorized-keys:\n";
        $y .= "      - " . yaml_quote($_) . "\n" for $s->{sshkeys}->@*;
    }

    if ($s->{networks}->@*) {
        $y .= "  network:\n";
        $y .= "    version: 2\n";
        $y .= "    ethernets:\n";
        my $dns_done;
        for my $net ($s->{networks}->@*) {
            my $i = '        ';
            $y .= "      net$net->{id}:\n";
            $y .= "${i}match:\n${i}  macaddress: " . yaml_quote($net->{mac}) . "\n";
            $y .= "${i}set-name: eth$net->{id}\n";
            $y .= "${i}dhcp4: true\n" if $net->{dhcp4};
            $y .= "${i}dhcp6: true\n" if ($net->{ip6mode} // '') eq 'dhcp';
            $y .= "${i}accept-ra: true\n" if ($net->{ip6mode} // '') eq 'auto';
            my @addresses;
            push @addresses, "$net->{ip}/$net->{prefix}" if $net->{ip};
            push @addresses, "$net->{ip6}/$net->{prefix6}" if $net->{ip6};
            if (@addresses) {
                $y .= "${i}addresses:\n";
                $y .= "${i}  - " . yaml_quote($_) . "\n" for @addresses;
            }
            my @routes;
            push @routes, ['0.0.0.0/0', $net->{gw}] if $net->{gw};
            push @routes, ['::/0', $net->{gw6}] if $net->{gw6};
            if (@routes) {
                $y .= "${i}routes:\n";
                for my $r (@routes) {
                    $y .= "${i}  - to: " . yaml_quote($r->[0]) . "\n";
                    $y .= "${i}    via: " . yaml_quote($r->[1]) . "\n";
                }
            }
            next if $dns_done;
            $dns_done = 1;
            if ($s->{nameservers}->@* || $s->{searchdomains}->@*) {
                $y .= "${i}nameservers:\n";
                if ($s->{nameservers}->@*) {
                    $y .= "${i}  addresses:\n";
                    $y .= "${i}    - " . yaml_quote($_) . "\n" for $s->{nameservers}->@*;
                }
                if ($s->{searchdomains}->@*) {
                    $y .= "${i}  search:\n";
                    $y .= "${i}    - " . yaml_quote($_) . "\n" for $s->{searchdomains}->@*;
                }
            }
        }
    }

    $y .= "  storage:\n";
    $y .= "    layout:\n";
    $y .= "      name: lvm\n";
    if (my $disk = $s->{disk}) {
        $y .= "      match:\n";
        $y .= "        path: " . yaml_quote("/dev/$disk") . "\n";
    }
    $y .= "  packages:\n";
    $y .= "    - qemu-guest-agent\n";
    $y .= "  late-commands:\n";
    $y .= "    - curtin in-target -- systemctl enable qemu-guest-agent || true\n";
    $y .= "  shutdown: reboot\n";

    return $y;
}

my sub windows_driver_versions {
    my ($winversion) = @_;

    return
          $winversion >= 11 ? ['w11', '2k25', '2k22']
        : $winversion >= 10 ? ['w10', '2k19', '2k16']
        : $winversion >= 8 ? ['w8.1', 'w8', '2k12R2', '2k12']
        : ['w7', '2k8R2'];
}

my sub windows_driver_arch {
    my ($arch) = @_;
    return $arch eq 'aarch64' ? 'ARM64' : $arch eq 'i386' ? 'x86' : 'amd64';
}

# Find the VirtIO drivers matching the guest in the local pxvirt-virtio-win package.
# Returns a hash of driver name => directory, empty if the package is not installed.
sub get_local_virtio_drivers {
    my ($winversion, $arch) = @_;

    my $res = {};
    return $res if !-d $VIRTIO_WIN_DIR;

    my $versions = windows_driver_versions($winversion);
    my $driver_arch = windows_driver_arch($arch);
    for my $driver (@$VIRTIO_WIN_DRIVERS) {
        for my $version (@$versions) {
            my $dir = "$VIRTIO_WIN_DIR/$driver/$version/$driver_arch";
            if (-d $dir) {
                $res->{$driver} = $dir;
                last;
            }
        }
    }
    return $res;
}

# Fallback if the drivers are not available locally: point Windows Setup to an attached
# virtio-win ISO.
my sub windows_driver_paths {
    my ($s) = @_;

    my $versions = windows_driver_versions($s->{winversion});
    my $arch = windows_driver_arch($s->{arch});

    # the VirtIO driver ISO can end up on any of these letters
    my @paths;
    for my $letter (qw(D E F G)) {
        for my $driver (qw(viostor vioscsi NetKVM Balloon vioserial)) {
            push @paths, "${letter}:\\$driver\\$_\\$arch" for @$versions;
        }
    }
    return \@paths;
}

sub generate_windows {
    my ($s) = @_;

    my $password = $s->{password};
    die "autoinstall: windows requires a password (cipassword)\n" if !defined($password);
    die "autoinstall: windows needs a plain text password, but cipassword is stored hashed -"
        . " set the OS type to Windows and set the password again\n"
        if is_hashed_password($password);

    my $arch = $s->{arch} eq 'aarch64' ? 'arm64' : $s->{arch} eq 'i386' ? 'x86' : 'amd64';
    my $comp = sub {
        my ($name) = @_;
        return "<component name=\"$name\" processorArchitecture=\"$arch\""
            . " publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\""
            . " xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\""
            . " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n";
    };

    my $locale = 'en-US';
    my $input_locale = $s->{input_locale};
    my $timezone = PVE::QemuServer::Timezone::windows_timezone($s->{timezone});
    my $computername = substr($s->{hostname}, 0, 15);
    my $username = $s->{username};
    my $password_x = xml_escape($password);
    my $disk = $s->{disk};

    my $x = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    $x .= "<unattend xmlns=\"urn:schemas-microsoft-com:unattend\">\n";

    # windowsPE pass
    $x .= "  <settings pass=\"windowsPE\">\n";
    $x .= "    " . $comp->('Microsoft-Windows-International-Core-WinPE');
    $x .= "      <SetupUILanguage><UILanguage>$locale</UILanguage></SetupUILanguage>\n";
    $x .= "      <InputLocale>$input_locale</InputLocale>\n";
    $x .= "      <SystemLocale>$locale</SystemLocale>\n";
    $x .= "      <UILanguage>$locale</UILanguage>\n";
    $x .= "      <UserLocale>$locale</UserLocale>\n";
    $x .= "    </component>\n";

    # bundled drivers are put into $WinPEDriver$ on the same ISO, which Windows Setup loads
    # automatically
    if (!$s->{virtio_drivers}->%*) {
        $x .= "    " . $comp->('Microsoft-Windows-PnpCustomizationsWinPE');
        $x .= "      <DriverPaths>\n";
        my $key = 1;
        for my $path (windows_driver_paths($s)->@*) {
            $x .= "        <PathAndCredentials wcm:action=\"add\" wcm:keyValue=\"$key\">"
                . "<Path>$path</Path></PathAndCredentials>\n";
            $key++;
        }
        $x .= "      </DriverPaths>\n";
        $x .= "    </component>\n";
    }

    $x .= "    " . $comp->('Microsoft-Windows-Setup');
    if ($s->{winversion} >= 11 && !($s->{tpm} && $s->{uefi})) {
        # allow installing Windows 11 on VMs without TPM / Secure Boot
        $x .= "      <RunSynchronous>\n";
        my $order = 1;
        for my $check (qw(BypassTPMCheck BypassSecureBootCheck BypassRAMCheck)) {
            my $cmd = "reg add HKLM\\SYSTEM\\Setup\\LabConfig /v $check /t REG_DWORD /d 1 /f";
            $x .= "        <RunSynchronousCommand wcm:action=\"add\"><Order>$order</Order>"
                . "<Path>$cmd</Path></RunSynchronousCommand>\n";
            $order++;
        }
        $x .= "      </RunSynchronous>\n";
    }
    $x .= "      <DiskConfiguration>\n";
    $x .= "        <Disk wcm:action=\"add\">\n";
    $x .= "          <DiskID>$disk</DiskID>\n";
    $x .= "          <WillWipeDisk>true</WillWipeDisk>\n";
    $x .= "          <CreatePartitions>\n";
    my $install_partition;
    if ($s->{uefi}) {
        $x .= "            <CreatePartition wcm:action=\"add\"><Order>1</Order><Type>EFI</Type>"
            . "<Size>300</Size></CreatePartition>\n";
        $x .= "            <CreatePartition wcm:action=\"add\"><Order>2</Order><Type>MSR</Type>"
            . "<Size>16</Size></CreatePartition>\n";
        $x .= "            <CreatePartition wcm:action=\"add\"><Order>3</Order><Type>Primary</Type>"
            . "<Extend>true</Extend></CreatePartition>\n";
        $x .= "          </CreatePartitions>\n";
        $x .= "          <ModifyPartitions>\n";
        $x .= "            <ModifyPartition wcm:action=\"add\"><Order>1</Order>"
            . "<PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label>"
            . "</ModifyPartition>\n";
        $x .= "            <ModifyPartition wcm:action=\"add\"><Order>2</Order>"
            . "<PartitionID>2</PartitionID></ModifyPartition>\n";
        $x .= "            <ModifyPartition wcm:action=\"add\"><Order>3</Order>"
            . "<PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label>"
            . "<Letter>C</Letter></ModifyPartition>\n";
        $install_partition = 3;
    } else {
        $x .= "            <CreatePartition wcm:action=\"add\"><Order>1</Order><Type>Primary</Type>"
            . "<Size>500</Size></CreatePartition>\n";
        $x .= "            <CreatePartition wcm:action=\"add\"><Order>2</Order><Type>Primary</Type>"
            . "<Extend>true</Extend></CreatePartition>\n";
        $x .= "          </CreatePartitions>\n";
        $x .= "          <ModifyPartitions>\n";
        $x .= "            <ModifyPartition wcm:action=\"add\"><Order>1</Order>"
            . "<PartitionID>1</PartitionID><Format>NTFS</Format><Label>System Reserved</Label>"
            . "<Active>true</Active></ModifyPartition>\n";
        $x .= "            <ModifyPartition wcm:action=\"add\"><Order>2</Order>"
            . "<PartitionID>2</PartitionID><Format>NTFS</Format><Label>Windows</Label>"
            . "<Letter>C</Letter></ModifyPartition>\n";
        $install_partition = 2;
    }
    $x .= "          </ModifyPartitions>\n";
    $x .= "        </Disk>\n";
    $x .= "      </DiskConfiguration>\n";
    $x .= "      <ImageInstall>\n";
    $x .= "        <OSImage>\n";
    $x .= "          <InstallTo><DiskID>$disk</DiskID>"
        . "<PartitionID>$install_partition</PartitionID></InstallTo>\n";
    my $edition = $s->{edition} // 1;
    my $image_key = $edition =~ m/^\d+$/ ? '/IMAGE/INDEX' : '/IMAGE/NAME';
    $x .= "          <InstallFrom><MetaData wcm:action=\"add\"><Key>$image_key</Key>"
        . "<Value>" . xml_escape($edition) . "</Value></MetaData></InstallFrom>\n";
    $x .= "        </OSImage>\n";
    $x .= "      </ImageInstall>\n";
    $x .= "      <UserData>\n";
    $x .= "        <AcceptEula>true</AcceptEula>\n";
    $x .= "        <FullName>" . xml_escape($username // 'Administrator') . "</FullName>\n";
    $x .= "        <Organization></Organization>\n";
    if (my $productkey = $s->{productkey}) {
        $x .= "        <ProductKey><Key>" . uc($productkey) . "</Key>"
            . "<WillShowUI>OnError</WillShowUI></ProductKey>\n";
    } else {
        # skip the product key page, e.g. Windows Server media asks for a key otherwise
        $x .= "        <ProductKey><WillShowUI>Never</WillShowUI></ProductKey>\n";
    }
    $x .= "      </UserData>\n";
    $x .= "    </component>\n";
    $x .= "  </settings>\n";

    # specialize pass
    $x .= "  <settings pass=\"specialize\">\n";
    $x .= "    " . $comp->('Microsoft-Windows-Shell-Setup');
    $x .= "      <ComputerName>" . xml_escape($computername) . "</ComputerName>\n";
    $x .= "      <TimeZone>" . xml_escape($timezone) . "</TimeZone>\n";
    $x .= "    </component>\n";
    # everything else is done by a script on the autoinstall ISO, see windows_specialize_script()
    $x .= "    " . $comp->('Microsoft-Windows-Deployment');
    $x .= "      <RunSynchronous>\n";
    $x .= "        <RunSynchronousCommand wcm:action=\"add\"><Order>1</Order>"
        . "<Description>Run autoinstall setup script</Description>"
        . "<Path>" . xml_escape($SPECIALIZE_COMMAND) . "</Path></RunSynchronousCommand>\n";
    $x .= "      </RunSynchronous>\n";
    $x .= "    </component>\n";
    if (my $domain = $s->{domain}) {
        $x .= "    " . $comp->('Microsoft-Windows-UnattendedJoin');
        $x .= "      <Identification>\n";
        $x .= "        <Credentials>\n";
        $x .= "          <Domain>" . xml_escape($domain->{name}) . "</Domain>\n";
        $x .= "          <Username>" . xml_escape($domain->{user}) . "</Username>\n";
        $x .= "          <Password>" . xml_escape($domain->{password}) . "</Password>\n";
        $x .= "        </Credentials>\n";
        $x .= "        <JoinDomain>" . xml_escape($domain->{name}) . "</JoinDomain>\n";
        if (defined(my $ou = $domain->{ou})) {
            $x .= "        <MachineObjectOU>" . xml_escape($ou) . "</MachineObjectOU>\n";
        }
        $x .= "      </Identification>\n";
        $x .= "    </component>\n";
    }
    if ($s->{rdp}) {
        $x .= "    " . $comp->('Microsoft-Windows-TerminalServices-LocalSessionManager');
        $x .= "      <fDenyTSConnections>false</fDenyTSConnections>\n";
        $x .= "    </component>\n";
    }

    my @static = grep { $_->{ip} || $_->{ip6} } $s->{networks}->@*;
    if (@static) {
        $x .= "    " . $comp->('Microsoft-Windows-TCPIP');
        $x .= "      <Interfaces>\n";
        for my $net (@static) {
            my $mac = uc($net->{mac} =~ s/:/-/gr);
            $x .= "        <Interface wcm:action=\"add\">\n";
            $x .= "          <Identifier>$mac</Identifier>\n";
            $x .= "          <Ipv4Settings><DhcpEnabled>false</DhcpEnabled></Ipv4Settings>\n"
                if $net->{ip};
            $x .= "          <Ipv6Settings><DhcpEnabled>false</DhcpEnabled></Ipv6Settings>\n"
                if $net->{ip6};
            $x .= "          <UnicastIpAddresses>\n";
            my $k = 1;
            for my $addr (
                ($net->{ip} ? "$net->{ip}/$net->{prefix}" : ()),
                ($net->{ip6} ? "$net->{ip6}/$net->{prefix6}" : ()),
            ) {
                $x .= "            <IpAddress wcm:action=\"add\" wcm:keyValue=\"$k\">"
                    . "$addr</IpAddress>\n";
                $k++;
            }
            $x .= "          </UnicastIpAddresses>\n";
            my @routes;
            push @routes, ['0.0.0.0/0', $net->{gw}] if $net->{ip} && $net->{gw};
            push @routes, ['::/0', $net->{gw6}] if $net->{ip6} && $net->{gw6};
            if (@routes) {
                $x .= "          <Routes>\n";
                my $r = 1;
                for my $route (@routes) {
                    $x .= "            <Route wcm:action=\"add\"><Identifier>$r</Identifier>"
                        . "<Prefix>$route->[0]</Prefix><NextHopAddress>$route->[1]"
                        . "</NextHopAddress></Route>\n";
                    $r++;
                }
                $x .= "          </Routes>\n";
            }
            $x .= "        </Interface>\n";
        }
        $x .= "      </Interfaces>\n";
        $x .= "    </component>\n";

        if ($s->{nameservers}->@* || $s->{searchdomains}->@*) {
            $x .= "    " . $comp->('Microsoft-Windows-DNS-Client');
            if (my $domain = $s->{searchdomains}->[0]) {
                $x .= "      <DNSDomain>" . xml_escape($domain) . "</DNSDomain>\n";
            }
            if ($s->{nameservers}->@*) {
                $x .= "      <Interfaces>\n";
                for my $net (@static) {
                    my $mac = uc($net->{mac} =~ s/:/-/gr);
                    $x .= "        <Interface wcm:action=\"add\">\n";
                    $x .= "          <Identifier>$mac</Identifier>\n";
                    $x .= "          <DNSServerSearchOrder>\n";
                    my $k = 1;
                    for my $ns ($s->{nameservers}->@*) {
                        $x .= "            <IpAddress wcm:action=\"add\" wcm:keyValue=\"$k\">"
                            . "$ns</IpAddress>\n";
                        $k++;
                    }
                    $x .= "          </DNSServerSearchOrder>\n";
                    $x .= "        </Interface>\n";
                }
                $x .= "      </Interfaces>\n";
            }
            $x .= "    </component>\n";
        }
    }
    $x .= "  </settings>\n";

    # oobeSystem pass
    $x .= "  <settings pass=\"oobeSystem\">\n";
    $x .= "    " . $comp->('Microsoft-Windows-International-Core');
    $x .= "      <InputLocale>$input_locale</InputLocale>\n";
    $x .= "      <SystemLocale>$locale</SystemLocale>\n";
    $x .= "      <UILanguage>$locale</UILanguage>\n";
    $x .= "      <UserLocale>$locale</UserLocale>\n";
    $x .= "    </component>\n";
    $x .= "    " . $comp->('Microsoft-Windows-Shell-Setup');
    # log on once automatically, so the system is ready to use after the installation
    my $autologon_user =
        defined($username) && lc($username) ne 'administrator' ? $username : 'Administrator';
    $x .= "      <AutoLogon>\n";
    $x .= "        <Enabled>true</Enabled>\n";
    $x .= "        <LogonCount>1</LogonCount>\n";
    $x .= "        <Domain>" . xml_escape($computername) . "</Domain>\n" if $s->{domain};
    $x .= "        <Username>" . xml_escape($autologon_user) . "</Username>\n";
    $x .= "        <Password><Value>$password_x</Value><PlainText>true</PlainText></Password>\n";
    $x .= "      </AutoLogon>\n";
    $x .= "      <OOBE>\n";
    $x .= "        <HideEULAPage>true</HideEULAPage>\n";
    $x .= "        <HideLocalAccountScreen>true</HideLocalAccountScreen>\n";
    $x .= "        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>\n";
    $x .= "        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>\n";
    $x .= "        <ProtectYourPC>3</ProtectYourPC>\n";
    $x .= "      </OOBE>\n";
    $x .= "      <UserAccounts>\n";
    $x .= "        <AdministratorPassword><Value>$password_x</Value>"
        . "<PlainText>true</PlainText></AdministratorPassword>\n";
    if (defined($username) && lc($username) ne 'administrator') {
        my $user_x = xml_escape($username);
        $x .= "        <LocalAccounts>\n";
        $x .= "          <LocalAccount wcm:action=\"add\">\n";
        $x .= "            <Name>$user_x</Name>\n";
        $x .= "            <DisplayName>$user_x</DisplayName>\n";
        $x .= "            <Group>Administrators</Group>\n";
        $x .= "            <Password><Value>$password_x</Value>"
            . "<PlainText>true</PlainText></Password>\n";
        $x .= "          </LocalAccount>\n";
        $x .= "        </LocalAccounts>\n";
    }
    $x .= "      </UserAccounts>\n";
    $x .= "    </component>\n";
    $x .= "  </settings>\n";
    $x .= "</unattend>\n";

    return $x;
}

# Settings applied in the specialize pass. Drivers come from a VirtIO driver ISO (virtio-win) if one
# is attached, otherwise from the drivers bundled on the autoinstall ISO.
sub windows_specialize_script {
    my ($s) = @_;

    my @lines = (
        '@echo off',
        'set "SRC=%~d0"',
        # do not require a network connection in the OOBE of Windows 11
        'reg.exe add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OOBE" /v BypassNRO'
            . ' /t REG_DWORD /d 1 /f',
        # no automatic BitLocker device encryption
        'reg.exe add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\BitLocker"'
            . ' /v PreventDeviceEncryption /t REG_DWORD /d 1 /f',
        # no hibernation and fast startup in a VM
        'powercfg.exe /hibernate off',
        'net.exe accounts /maxpwage:UNLIMITED',
    );

    if ($s->{rdp}) {
        # the rule group is given by its resource ID, which works for all languages
        push @lines, 'netsh.exe advfirewall firewall set rule group="@FirewallAPI.dll,-28752"'
            . ' new enable=Yes';
    }

    my $bundled = '"%SRC%\\$WinPEDriver$"';
    my $pnputil = "pnputil.exe /add-driver \"%SRC%\\\$WinPEDriver\$\\*.inf\" /subdirs /install";
    if ($s->{arch} eq 'x86_64') {
        push @lines,
            'set "VIRTIO_MSI="',
            'for %%d in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do'
                . ' if exist "%%d:\\virtio-win-gt-x64.msi" set "VIRTIO_MSI=%%d:\\virtio-win-gt-x64.msi"',
            'if defined VIRTIO_MSI (',
            '    msiexec.exe /i "%VIRTIO_MSI%" /qn /norestart',
            ") else if exist $bundled (",
            "    $pnputil",
            ')';
    } else {
        push @lines, "if exist $bundled $pnputil";
    }

    if (my $qemu_ga = $s->{qemu_ga}) {
        my $msi = '"%SRC%\\' . ($qemu_ga =~ s|/|\\|gr) . '"';
        push @lines, "msiexec.exe /i $msi /qn /norestart";
    }

    return join("\r\n", @lines) . "\r\n";
}

my $generators = {
    windows => \&generate_windows,
    kickstart => \&generate_kickstart,
    ubuntu => \&generate_ubuntu,
};

# Returns ($type, $files) where $files maps ISO paths to their contents.
sub get_files {
    my ($conf, $vmid) = @_;

    my $ai = parse_autoinstall($conf) // {};
    my $type = get_type($conf, $ai);
    my $info = $installer_types->{$type} or die "unknown autoinstall type '$type'\n";

    my $settings = get_settings($conf, $vmid, $ai, $type);

    my $extra_files = {};
    if ($type eq 'windows') {
        my $drivers = get_local_virtio_drivers($settings->{winversion}, $settings->{arch});
        $settings->{virtio_drivers} = $drivers;
        for my $driver (sort keys %$drivers) {
            my $dir = $drivers->{$driver};
            opendir(my $dh, $dir) or die "unable to open '$dir' - $!\n";
            for my $entry (sort readdir($dh)) {
                # untaint, the names end up as file names on the autoinstall ISO
                my ($name) = $entry =~ m/^([A-Za-z0-9][A-Za-z0-9._+-]*)$/ or next;
                next if !-f "$dir/$name";
                $extra_files->{"/\$WinPEDriver\$/$driver/$name"} =
                    PVE::Tools::file_get_contents("$dir/$name", 64 * 1024 * 1024);
            }
            closedir($dh);
        }

        # current guest agent builds only support Windows 10 / Server 2016 and newer
        my $msi = $QEMU_GA_MSI->{ $settings->{arch} };
        if ($msi && $settings->{winversion} >= 10 && -f "$VIRTIO_WIN_DIR/$msi") {
            $settings->{qemu_ga} = $msi;
            $extra_files->{"/$msi"} =
                PVE::Tools::file_get_contents("$VIRTIO_WIN_DIR/$msi", 64 * 1024 * 1024);
        }
    }

    my $content;
    if (my $volid = $ai->{file}) {
        my $storecfg = PVE::Storage::config();
        $content =
            PVE::QemuServer::Cloudinit::read_cloudinit_snippets_file($storecfg, $volid);
        $content = render_template($content, get_template_variables($settings));
    } else {
        $content = $generators->{$type}->($settings);
        $extra_files->{$SPECIALIZE_SCRIPT} = windows_specialize_script($settings)
            if $type eq 'windows';
    }

    die "autoinstall file too big (> 3 MiB)\n" if length($content) > 3 * 1024 * 1024;

    my $files = { %$extra_files, $info->{file} => $content };
    if ($type eq 'ubuntu') {
        my $instance_id = Digest::SHA::sha1_hex($content);
        $files->{'/meta-data'} = "instance-id: $instance_id\n";
    }

    return ($type, $files);
}

sub generate {
    my ($conf, $vmid, $drive, $volname, $storeid) = @_;

    my ($type, $files) = get_files($conf, $vmid);
    my $info = $installer_types->{$type};

    print "generating autoinstall ($type) configuration\n";
    PVE::QemuServer::Cloudinit::commit_cloudinit_disk(
        $conf, $vmid, $drive, $volname, $storeid, $files, $info->{label}, $info->{joliet},
    );
}

sub dump {
    my ($conf, $vmid, $mask_password) = @_;

    return '' if !is_enabled($conf);

    my $dump_conf = $conf;
    if ($mask_password && defined($conf->{cipassword})) {
        $dump_conf = { %$conf, cipassword => '**********' };
    }
    if ($mask_password && defined($conf->{cidomainpassword})) {
        $dump_conf = { %$dump_conf, cidomainpassword => '**********' };
    }

    my ($type, $files) = get_files($dump_conf, $vmid);

    return $files->{ $installer_types->{$type}->{file} };
}

1;
