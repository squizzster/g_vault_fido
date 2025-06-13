#!/usr/bin/env perl

#######  [v1.0 loader]  ########
use v5.14; use strict;use warnings;use utf8;binmode(STDIN,':encoding(UTF-8)');binmode(STDOUT,':encoding(UTF-8)');binmode(STDERR,':encoding(UTF-8)');$|=1;my$g;use FindBin qw($RealBin $RealScript);BEGIN{$g->{dir}={exe=>"$RealBin/$RealScript",path=>$RealBin,lib=>"$RealBin/lib",conf=>"$RealBin/conf"};-r$g->{dir}{exe}or die"FATAL:$g->{dir}{exe} not found\n";my($u,$gid)=(stat $g->{dir}{exe})[4,5];defined$u or die"FATAL:stat failed\n";$g->{user}={uid=>$u,gid=>$gid}}; BEGIN{($g->{user}{uid}||$g->{user}{gid})&& do{use lib"$g->{dir}{path}/lib";require set_uuid;set_uuid::set_uuid($g->{user}{uid},$g->{user}{gid},1)||die"Failed to drop privileges: $!"}}; use lib $g->{dir}{path}.'/lib';my%seen;my@f=grep{my$b=$_;$b=~s{^.*/}{};!$seen{$b}++}(glob("$g->{dir}{lib}/*.pm"),glob("common_lib/*.pm"));my$e='';eval{for(@f){next unless -f$_&&/\.pm$/;open(my$h,'<',$_)or($e.="Can't open $_: $!\n",next);my$p=0;for(1..10){last unless defined(my$l=<$h>);$p=1,last if$l=~/^\s*package\s+\S+;/}close$h;if($p){(my$m=$_)=~s{^.*/}{};$m=~s/\.pm$//;$m=~s{/}{::}g;eval"require $m" or $e.="Error using $m: $@\n"}else{do$_ or $e.="Error in file $_:[".($@||"Make sure it evaluates to 'true'")."]\n"}}};$e.=$@ if$@;$e and print STDERR"\nCompilation failed:\n$e"and exit 1;undef $e;undef @f;undef %seen; package main; #### [loader done] ####;
#!/usr/bin/env perl

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
use fast_file_hash             ();          # requires fast_file_hash::fast_file_hash
use read_write                 ();          # requires read_write::read / write

# ─── CONSTANTS ─────────────────────────────────────────────────────────────
use constant {
    MASTER_SIZE   => 64,                      # 512-bit master key
    MASTER_PATH   => '/root/master_64_x.bin',
    TAG_PREFIX    => 'TEAMLOCK-v2|',          # domain-separation string
    XATTR_PREFIX  => '_gv_x_',                  # file-attr namespace
    XATTR_CONFIG  => '_gv_c_',                  # file-attr namespace
};

# ─── INTEGRITY MAP & DEFAULT ──────────────────────────────────────────────
my %CODE_MAP = (
    fp => '_full_path',
    bn => '_basename',
    di => '_device_id',
    in => '_inode',
    lc => '_link_count',
    ou => '_owner_uid',
    og => '_group_gid',
    pe => '_permissions',
    em => '_epoch_modify',
    fh => '_file_hash',
);

use constant PARANOID => {
    _full_path    => 1,
    _basename     => 1,
    _device_id    => 1,
    _inode        => 1,
    _link_count   => 1,
    _owner_uid    => 1,
    _group_gid    => 1,
    _permissions  => 1,
    _epoch_modify => 1,
    _file_hash    => 1,
};

use constant MINIMAL => {
    _full_path    => 1,  
    _basename     => 1,
    _device_id    => 0, 
    _inode        => 0, 
    _link_count   => 0,
    _owner_uid    => 1, 
    _group_gid    => 1,
    _permissions  => 1, 
    _epoch_modify => 0, 
    _file_hash    => 0,
};


# ─── TEAM TABLE ────────────────────────────────────────────────────────────
# Each team entry MUST contain:
#   executable – absolute path
#   integrity  – executable integrity spec (hashref or arrayref of short codes)
#   configs    – arrayref of { file => '/path', integrity => … }
#
# Integrity short-codes map:
#   fp  bn  di  in  lc  ou  og  pe  em  fh
#
# Add or remove teams as required (max 1024).
my %TEAMS = (
    db => {
        executable => '/usr/sbin/mysqld',
        integrity  => [qw(fp bn di in lc ou og pe em fh)],
        configs    => [
            {
                file      => '/etc/my.cnf.d/server.cnf',
                integrity => [qw(fp bn di in lc ou og pe em fh)],
            },
            {
                file      => '/etc/mysql.key',
                integrity => { _full_path => 1, _basename => 1, _device_id => 1 },
            },
        ],
    },

    cat1 => {
        executable => '/usr/bin/cat',
        integrity  => PARANOID,
        configs    => [
            { file => '/tmp/hello_1.txt', integrity => [qw(fp bn di in lc ou og pe em fh)] },
            { file => '/tmp/hello_2.txt', integrity => [qw(fp bn di in lc ou og pe em fh)] },
            { file => '/etc/mysql.key',   integrity => [qw(fp bn di in lc ou og pe em fh)] },
        ],
    },

    cat2 => {
        executable => '/usr/bin/cat',
        integrity  => PARANOID,
        configs    => [
            { file => '/tmp/hello_again.txt', integrity => [qw(fp bn di in lc ou og pe em fh)] },
            { file => '/etc/mysql.key',       integrity => [qw(fp bn di in lc ou og pe em fh)] },
        ],
    },
    # … add further teams here …
);

# ────────────────────────────────────────────────────────────────────────────
main();
exit 0;

# ─── FUNCTIONS ─────────────────────────────────────────────────────────────

sub main {
    my ($master, $err) = init_master(MASTER_PATH, MASTER_SIZE);
    $master // die "Cannot initialise MASTER key: $err; bailing out";

    my $verify   = 1;
    my $register = 1;

    for my $team (sort keys %TEAMS) {
        my $ref = $TEAMS{$team};

        my ($ok, $msg);
        if ($register) {
            say "Registering team “$team” → $ref->{executable}";
            ($ok, $msg) = register_team($team, $ref, $master);
        }

        if ($verify) {
            my $have = get_file_attr($ref->{executable}, XATTR_PREFIX . ".$team");

            if ($have) {
                ($ok, $msg) = verify_team($team, $ref, $master);
            }
            else {
                # not yet registered
            }
        }
        warn "$msg\n" if defined $msg && !$ok;
    }
}

# ────────────────────────────────────────────────────────────────────────────
sub normalize_integrity_cfg {
    my ($spec) = @_;

    $spec //= PARANOID;

    if (ref $spec eq 'HASH') {
        return $spec;
    }
    elsif (ref $spec eq 'ARRAY') {
        my %cfg;
        for my $code (@$spec) {
            my $key = $CODE_MAP{$code};
            next unless defined $key;
            $cfg{$key} = 1;
        }
        return \%cfg;
    }
    else {
        return PARANOID;
    }
}

# Lightweight wrapper around fast_file_hash that always passes cfg
sub file_hash {
    my ($path, $cfg) = @_;
    $cfg = normalize_integrity_cfg($cfg);
    print "CFG FOR FILE HASH=> [$path] => " . ( dump $cfg ); print "\n";
    return ( fast_file_hash::fast_file_hash($path, $cfg) );
}

# ---------------------------------------------------------------------------
sub register_team {
    my ($key, $team, $master) = @_;

    my $exe = $team->{executable}
      or return (undef, "[register:$key] no executable");
    my $exe_cfg = normalize_integrity_cfg($team->{integrity});

    my $configs = $team->{configs};
    return (undef, "[register:$key] no config files") unless $configs && @$configs;
    return (undef, "[register:$key] exe not readable: $exe") unless -r $exe;

    my $Ki   = hmac('BLAKE2b_256', $master, "TEAM-$key");
    my ($data, $cfg) = TAG_PREFIX . file_hash($exe, $exe_cfg);

    for my $entry (@$configs) {
        my $file = $entry->{file}
          or return (undef, "[register:$key] config entry missing 'file'");
        my $cfg = normalize_integrity_cfg($entry->{integrity});
        print dump $cfg;

        return (undef, "[register:$key] cfg not readable: $file") unless -r $file;
        $data .= file_hash($file, $cfg);
    }

    my $tag = hmac('BLAKE2b_256', $Ki, $data);
    set_file_attr($exe, XATTR_PREFIX . ".$key", $tag) or return (undef, "[register:$key] failed to set xattr");

    say "[register:$key] OK.";
    return (1, '');
}

# ---------------------------------------------------------------------------
sub verify_team {
    my ($key, $team, $master) = @_;

    my $exe = $team->{executable}
      or return (undef, "[verify:$key] no executable");
    my $exe_cfg = normalize_integrity_cfg($team->{integrity});

    my $configs = $team->{configs}
      or return (undef, "[verify:$key] no config files");

    my $tag = get_file_attr($exe, XATTR_PREFIX . ".$key")
      or return (undef, "[verify:$key] missing exe tag");

    my $Ki   = hmac('BLAKE2b_256', $master, "TEAM-$key");
    my $data = TAG_PREFIX . file_hash($exe, $exe_cfg);

    for my $entry (@$configs) {
        my $file = $entry->{file}
          or return (undef, "[verify:$key] config entry missing 'file'");
        my $cfg = normalize_integrity_cfg($entry->{integrity});

        return (undef, "[verify:$key] cfg not readable: $file") unless -r $file;
        $data .= file_hash($file, $cfg);
    }

    my $candidate = hmac('BLAKE2b_256', $Ki, $data);
    return (undef, "[verify:$key] FAILED for $exe") unless secure_bcmp($candidate, $tag);

    say "[verify:$key] OK.";
    return (1, '');
}

# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
sub secure_bcmp {
    my ($a, $b) = @_;
    return unless defined $a && defined $b && length($a) == length($b);

    my $diff = 0;
    $diff |= ord(substr($a, $_, 1)) ^ ord(substr($b, $_, 1))
      for 0 .. length($a) - 1;

    return $diff ? undef : 1;
}

