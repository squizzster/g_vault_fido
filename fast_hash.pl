#!/usr/bin/env perl
use strict;
use warnings;
use AnyEvent;

use lib 'lib';

use Fifo;
use Data::Dump qw(dump);

use fast_file_hash qw(fast_file_hash);

# configuration:
my %config =
(
    include_full_path    => 1,   # canonical abs path; covers basename implicitly
    include_basename     => 1,   # ← harmless duplication due to full-path-rule, keeps UX simple
    include_device_id    => 0,   # portability: same file restored on another fs OK
    include_inode        => 1,   # inode must match; detects “replace-in-place” tricks - you must update with same inode
    include_link_count   => 1,   # hard-link anomalies show up
    include_owner_uid    => 1,   # root→non-root or vice-versa trips digest
    include_group_gid    => 1,   # same for group
    include_permissions  => 1,   # mode bits (suid, sgid, +x) are critical
    include_epoch_modify => 0,   # mtime drift often indicates tampering but you would need to update the config file.
    include_file_hash    => 0,   # sample-based BLAKE2b-256 of the contents but you would need to update the config file.
    include_our_tag      => '',  # leave empty unless you want a policy tag
    hash                 => '86cf4712d624369e07719891bdefda7690b448baba80694d6035bb582605cb5c',
    secure               => '86cf4712d624369e07719891bdefda7690b448baba80694d6035bb582605cb5c',
);



# You can override defaults by passing a second argument as a JSON or key=value string,
# parsed here if present (optional). For now we stick to defaults.

my $file = $ARGV[0];
unless (defined $file) {
    warn "Usage: $0 <filename>\n";
    exit 1;
}

# Compute composite hash
my $hash = fast_file_hash($file, \%config);

# On error, fast_file_hash returns undef
if (defined $hash) {
    print "$hash\n";
    exit 0;
} else {
    warn "Failed to compute hash for '$file'\n";
    exit 2;
}

