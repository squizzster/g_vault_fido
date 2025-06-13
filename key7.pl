#!/usr/bin/env perl

#######  [v1.0 loader]  ########
use v5.14; use strict;use warnings;use utf8;binmode(STDIN,':encoding(UTF-8)');binmode(STDOUT,':encoding(UTF-8)');binmode(STDERR,':encoding(UTF-8)');$|=1;my$g;use FindBin qw($RealBin $RealScript);BEGIN{$g->{dir}={exe=>"$RealBin/$RealScript",path=>$RealBin,lib=>"$RealBin/lib",conf=>"$RealBin/conf"};-r$g->{dir}{exe}or die"FATAL:$g->{dir}{exe} not found\n";my($u,$gid)=(stat $g->{dir}{exe})[4,5];defined$u or die"FATAL:stat failed\n";$g->{user}={uid=>$u,gid=>$gid}}; BEGIN{($g->{user}{uid}||$g->{user}{gid})&& do{use lib"$g->{dir}{path}/lib";require set_uuid;set_uuid::set_uuid($g->{user}{uid},$g->{user}{gid},1)||die"Failed to drop privileges: $!"}}; use lib $g->{dir}{path}.'/lib';my%seen;my@f=grep{my$b=$_;$b=~s{^.*/}{};!$seen{$b}++}(glob("$g->{dir}{lib}/*.pm"),glob("common_lib/*.pm"));my$e='';eval{for(@f){next unless -f$_&&/\.pm$/;open(my$h,'<',$_)or($e.="Can't open $_: $!\n",next);my$p=0;for(1..10){last unless defined(my$l=<$h>);$p=1,last if$l=~/^\s*package\s+\S+;/}close$h;if($p){(my$m=$_)=~s{^.*/}{};$m=~s/\.pm$//;$m=~s{/}{::}g;eval"require $m" or $e.="Error using $m: $@\n"}else{do$_ or $e.="Error in file $_:[".($@||"Make sure it evaluates to 'true'")."]\n"}}};$e.=$@ if$@;$e and print STDERR"\nCompilation failed:\n$e"and exit 1;undef $e;undef @f;undef %seen; package main; #### [loader done] ####;

use v5.26;
use warnings;
use Log::Any::Adapter;     Log::Any::Adapter->set('Stderr');
use Fcntl qw(:DEFAULT :flock);

# ─── CPAN modules ──────────────────────────────────────────────────────────
use Crypt::PRNG                 qw(random_bytes);
use Crypt::Mac::HMAC            qw(hmac);
use Crypt::Digest::BLAKE2b_256  qw(blake2b_256);
use file_attr                   qw(get_file_attr set_file_attr del_file_attr);
use Data::Dump                  qw(dump);

# ─── CONSTANTS ─────────────────────────────────────────────────────────────
use constant {
    MASTER_SIZE   => 64,                      # 512-bit master key
    MASTER_PATH   => '/root/master_64_x.bin',
    TAG_PREFIX    => 'TEAMLOCK-v2|',          # domain-separation string
    XATTR_PREFIX  => '_gv_',                  # file-attr namespace
};

# ─── TEAM TABLE ────────────────────────────────────────────────────────────
my %TEAMS = (
    db   => {
        exe  => '/usr/sbin/mysqld',
        cfgs => [
            '/etc/my.cnf.d/server.cnf',
            '/etc/mysql.key',
        ],
    },
    cat1 => {
        exe  => '/usr/bin/cat',
        cfgs => [
            '/tmp/hello_1.txt',
            '/tmp/hello_2.txt',
            '/etc/mysql.key',
        ],
    },
    cat2 => {
        exe  => '/usr/bin/cat',
        cfgs => [
            '/tmp/hello_again.txt',
            '/etc/mysql.key',
        ],
    },
    # … add up to 1024 such entries …
);

# ────────────────────────────────────────────────────────────────────────────
main();
exit 0;

sub main {
    my ($master, $err) = init_master(MASTER_PATH, MASTER_SIZE);
    $master // die "Cannot initialise MASTER key: $err; bailing out";

    my $verify   = 1;
    my $register = 0;

    for my $key (sort keys %TEAMS) {
        my $exe  = $TEAMS{$key}{exe};
        my $cfgs = $TEAMS{$key}{cfgs};

        my ($ok, $msg);
        if ( $register)  {
            # REGISTER
            say "Registering team “$key” → $exe";
            ($ok, $msg) = register_team($key, $exe, $cfgs, $master);
        }

        if ( $verify ) {
            my $h = get_file_attr($exe, XATTR_PREFIX . ".$key");

            if ( my $have = get_file_attr($exe, XATTR_PREFIX . ".$key") ) {
                # already registered → verify
                ($ok, $msg) = verify_team($key, $exe, $cfgs, $master);
            }
            else {
            }
        }
        warn "$msg\n" unless $ok;
    }
}

sub init_master {
    my ($path, $size) = @_;
    unless (-e $path) {
        read_write::write($path, random_bytes($size))
          or return wantarray ? (undef, "Failed to create $path: $!") : undef;
        chmod 0400, $path or return wantarray ? (undef, "chmod $path: $!") : undef;
        say "Generated new $size-byte MASTER key at $path";
    }

    my $m = read_write::read($path);
    unless (defined $m && length($m) == $size) {
        my $err = "MASTER wrong length: "
                . (defined $m ? length($m) : 'undef') . " bytes";
        return wantarray ? (undef, $err) : undef;
    }
    return wantarray ? ($m, '') : $m;
}

sub file_hash {
    my $path = shift;
    return fast_file_hash::fast_file_hash($path);
}

sub register_team {
    my ($key, $exe, $cfgs, $master) = @_;

    return (undef, "[register:$key] no config files") unless @$cfgs;
    return (undef, "[register:$key] exe not readable: $exe") unless -r $exe;

    my $Ki = hmac('BLAKE2b_256', $master, "TEAM-$key");

    my $data = TAG_PREFIX . file_hash($exe);
    for my $cfg (@$cfgs) {
        return (undef, "[register:$key] cfg not readable: $cfg") unless -r $cfg;
        $data .= file_hash($cfg);
    }

    my $tag = hmac('BLAKE2b_256', $Ki, $data);
    set_file_attr($exe, XATTR_PREFIX . ".$key", $tag)
      or return (undef, "[register:$key] failed to set xattr");

    say "[register:$key] OK.";
    return (1, '');
}

sub verify_team {
    my ($key, $exe, $cfgs, $master) = @_;

    my $tag = get_file_attr($exe, XATTR_PREFIX . ".$key")
      or return (undef, "[verify:$key] missing exe tag");

    my $Ki = hmac('BLAKE2b_256', $master, "TEAM-$key");
    my $data = TAG_PREFIX . file_hash($exe);
    for my $cfg (@$cfgs) {
        return (undef, "[verify:$key] cfg not readable: $cfg") unless -r $cfg;
        $data .= file_hash($cfg);
    }

    my $candidate = hmac('BLAKE2b_256', $Ki, $data);
    return (undef, "[verify:$key] FAILED for $exe") unless secure_bcmp($candidate, $tag);

    say "[verify:$key] OK.";
    return (1, '');
}

sub secure_bcmp {
    my ($a, $b) = @_;
    return unless defined $a && defined $b && length($a) == length($b);

    my $diff = 0;
    $diff |= ord(substr($a, $_, 1)) ^ ord(substr($b, $_, 1))
      for 0 .. length($a)-1;

    return $diff ? undef : 1;
}


