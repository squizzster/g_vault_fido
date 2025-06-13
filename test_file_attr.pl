#!/usr/bin/env perl
use strict;
use warnings;
use lib 'lib';
use Data::Dump qw(dump);

use file_attr qw(get_file_attr set_file_attr del_file_attr);

my $file = '/tmp/test_file.tmp';
my $attr = 'user.g_vault.fifo';

### so we specify the filename... and then we get the hash of the filename... 
### So somehow this FIFO needs to write if any filename actually matches... ?


my $test_value = {
    caller => {
        _full_path    => 1,   # canonical abs path; covers basename implicitly
        _basename     => 1,   # ← harmless duplication due to full-path-rule, keeps UX simple
        _device_id    => 0,   # portability: same file restored on another fs OK
        _inode        => 1,   # inode must match; detects “replace-in-place” tricks - you must update with same inode
        _link_count   => 1,   # hard-link anomalies show up
        _owner_uid    => 1,   # root→non-root or vice-versa trips digest
        _group_gid    => 1,   # same for group
        _permissions  => 1,   # mode bits (suid, sgid, +x) are critical
        _epoch_modify => 0,   # mtime drift often indicates tampering but you would need to update the config file.
        _file_hash    => 0,   # sample-based BLAKE2b-256 of the contents but you would need to update the config file.
        _our_tag      => '',  # leave empty unless you want a policy tag
    },
    pid => {
        _is_parent_of  => 1,
        _curr_work_dir  => '',
        _init_is_ppid   => 1,
        _init_is_ppid   => 1,

    }
};


# Ensure the test file exists
unless (-e $file) {
    open my $fh, '>', $file or die "Can't create $file: $!";
    print $fh "dummy\n";
    close $fh;
    print "Created $file\n";
}

#print "\nSetting attribute [$attr] to [$test_value]...\n";
#my $set_ok = set_file_attr($file, $attr, $test_value);
#print $set_ok ? "Set OK\n" : "Set failed\n";

print "\nGetting attribute [$attr]...\n";

my $woof = file_attr::get_file_attr_raw($file, $attr);
print dump $woof;
print "\n";

my $val = get_file_attr($file, $attr);
print defined $val && length($val)
    ? "Got value: " . ( dump $val ) . "\n"
    : "No attribute or get failed\n";

print "\nDone.\n"; exit;

print "\nDeleting attribute [$attr]...\n";
my $del_ok = del_file_attr($file, $attr);
print $del_ok ? "Delete OK\n" : "Delete failed\n";

print "\nTrying to get attribute [$attr] after deletion...\n";
$val = get_file_attr($file, $attr);
print defined $val && length($val)
    ? "Got value: [$val]\n"
    : "Attribute is gone (as expected)\n";

print "\nDone.\n";

