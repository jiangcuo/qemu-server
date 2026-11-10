#!/usr/bin/perl

# Tests the shared QGA arbitration lock used by PVE::QMPClient and the
# qmeventd capture worker. The lock logic lives in PVE::QMPClient.pm; the
# transport modules it pulls in (IO::Multiplex, PVE::IPCC) are unrelated to the
# lock and are replaced here by minimal compile-only stubs so the real lock
# code can be exercised without a full PVE/QEMU runtime.

use strict;
use warnings;

use lib qw(..);

use FindBin qw($Bin);
use File::Temp qw(tempdir);
use Fcntl qw(O_RDWR O_CREAT O_NOFOLLOW LOCK_UN F_GETFD FD_CLOEXEC);
use Test::More;

no warnings 'once'; # package variable set once for the test only

# Sibling repositories, when checked out next to qemu-server, for the PVE
# modules PVE::QemuServer::Helpers pulls in.
for my $rel (qw(../../../pve-common/src ../../../pve-cluster/src)) {
    my $dir = "$Bin/$rel";
    unshift @INC, $dir if -d $dir;
}

sub write_file {
    my ($path, $content) = @_;
    open(my $fh, '>', $path) or die "cannot write $path - $!";
    print {$fh} $content;
    close($fh);
}

# --- controlled stubs for modules that are not part of the lock logic -----
my $stubdir = tempdir(CLEANUP => 1);
mkdir "$stubdir/IO" or die $!;
mkdir "$stubdir/PVE" or die $!;
write_file("$stubdir/IO/Multiplex.pm", <<'EOF');
package IO::Multiplex;
sub new { bless {}, shift }
sub set_callback_object { }
sub add { }
sub set_timeout { }
sub write { }
sub close { }
sub loop { }
sub endloop { }
sub inbuffer { }
1;
EOF
write_file("$stubdir/PVE/IPCC.pm", <<'EOF');
package PVE::IPCC;
sub sendfd { return -1 }
1;
EOF
unshift @INC, $stubdir;

require PVE::QMPClient;

# --- tests ----------------------------------------------------------------

my $lockdir = tempdir(CLEANUP => 1);
$PVE::QMPClient::QGA_LOCK_DIR = $lockdir;

is(PVE::QMPClient::qga_lock_path(100),
   "$lockdir/100.qga.lock", 'lock path is <dir>/<vmid>.qga.lock');

my $fh = PVE::QMPClient::qga_lock_acquire(100, 5);
ok(defined($fh), 'acquire returns a file handle');
ok(-e "$lockdir/100.qga.lock", 'lock file exists');
is(sprintf('%04o', (stat("$lockdir/100.qga.lock"))[2] & 07777), '0600',
   'lock file is root-private 0600');

# A second independent open in the same process conflicts: this models a
# concurrent holder and must fail within the bounded timeout.
my $died = '';
eval { PVE::QMPClient::qga_lock_acquire(100, 0.3); 1; } or $died = $@;
like($died, qr/timeout acquiring QGA lock/, 'contended acquire times out');

# release makes the lock available again
PVE::QMPClient::qga_lock_release($fh);
my $fh2 = PVE::QMPClient::qga_lock_acquire(100, 1);
ok(defined($fh2), 'acquire succeeds after release');
PVE::QMPClient::qga_lock_release($fh2);

# releasing an undefined handle is a harmless no-op
eval { PVE::QMPClient::qga_lock_release(undef); 1; } or die "release(undef): $@";
pass('release(undef) is a no-op');

# a symlinked lock file must be refused (O_NOFOLLOW), not followed
my $target = "$lockdir/real-target";
write_file($target, "x\n");
my $link = "$lockdir/200.qga.lock";
symlink($target, $link) or die "symlink: $!";
my $err = '';
eval { PVE::QMPClient::qga_lock_acquire(200, 0.3); 1; } or $err = $@;
like($err, qr/unable to open QGA lock/, 'symlink lock path is refused');

# a pre-existing looser mode is tightened to 0600
my $loose = "$lockdir/300.qga.lock";
write_file($loose, "");
chmod 0644, $loose;
my $fh3 = PVE::QMPClient::qga_lock_acquire(300, 1);
is(sprintf('%04o', (stat($loose))[2] & 07777), '0600',
   'pre-existing loose mode is tightened to 0600');

# the tightening is done on the already-opened handle (fchmod), so it is not
# affected by racing the path; verify the descriptor actually got the flag and
# is cleared to close-on-exec.
is(fcntl($fh3, F_GETFD, 0) & FD_CLOEXEC, FD_CLOEXEC,
   'lock descriptor is close-on-exec');
PVE::QMPClient::qga_lock_release($fh3);

# no descriptor is leaked when acquire fails (contended timeout path)
sub open_lock_fds {
    my ($dir) = @_;
    my @fds;
    opendir(my $dh, '/proc/self/fd') or die "opendir /proc/self/fd: $!";
    for my $entry (readdir($dh)) {
        next if $entry !~ m/^\d+$/;
        my $link = readlink("/proc/self/fd/$entry");
        push @fds, $entry if defined($link) && index($link, $dir) == 0;
    }
    closedir($dh);
    return scalar @fds;
}

my $held = PVE::QMPClient::qga_lock_acquire(400, 1);
my $fds_before = open_lock_fds($lockdir);
my $timeout_err = '';
eval { PVE::QMPClient::qga_lock_acquire(400, 0.3); 1 } or $timeout_err = $@;
like($timeout_err, qr/timeout acquiring QGA lock/, 'contended acquire still times out');
is(open_lock_fds($lockdir), $fds_before,
   'no lock descriptor leaked when acquire fails');
PVE::QMPClient::qga_lock_release($held);

done_testing();
