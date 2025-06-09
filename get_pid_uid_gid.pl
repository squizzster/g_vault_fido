#!/usr/bin/env perl
use strict;
use warnings;

sub get_uid_gid_of_pid {
    my ($pid) = @_;
    return unless defined $pid && $pid =~ /^\d+$/;

    my $status_path = "/proc/$pid/status";
    open my $fh, '<', $status_path or return;
    local $/;  # slurp mode
    my $content = <$fh>;
    close $fh;

    if ($content =~ /^Uid:\s+(\d+).*?^Gid:\s+(\d+)/ms) {
        return ($1, $2);
    }
    return;
}

# -------------------------
# Main entry point
# -------------------------
my $pid = shift @ARGV // $$;
my ($uid, $gid) = get_uid_gid_of_pid($pid);

if (defined $uid) {
    print "PID $pid → UID: $uid, GID: $gid\n";
} else {
    print "Error: Could not extract UID/GID for PID $pid\n";
    exit 1;
}

