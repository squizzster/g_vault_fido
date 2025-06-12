#!/usr/bin/env perl
use strict;
use warnings;
use AnyEvent;

use lib 'lib';

use Fifo;
use Data::Dump qw(dump);

use fast_file_hash qw(fast_file_hash);

# configuration:
my %config = (
    include_full_path    => 1,                   # full filename (e.g. /foo/bar/baz)
    include_basename     => 1,                   # base filename (e.g. baz)
    include_inode        => 0,                   # inode number
    include_owner_uid    => 1,                   # owner UID
    include_group_gid    => 1,                   # group GID
    include_epoch_modify => 0,                   # Modify date/time epoch
    include_permissions  => 1,                   # file mode (octal e.g. 0755)
    include_file_hash    => 0,                   # actual file content hash
    include_our_tag      => '',                  # should be unique across your estate, company, host, server, your choice. (can be '').
);

#%config = ();

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

