#!/usr/bin/env perl

#######  [v1.0 loader]  ########
use v5.14; use strict;use warnings;use utf8;binmode(STDIN,':encoding(UTF-8)');binmode(STDOUT,':encoding(UTF-8)');binmode(STDERR,':encoding(UTF-8)');$|=1;my$g;use FindBin qw($RealBin $RealScript);BEGIN{$g->{dir}={exe=>"$RealBin/$RealScript",path=>$RealBin,lib=>"$RealBin/lib",conf=>"$RealBin/conf"};-r$g->{dir}{exe}or die"FATAL:$g->{dir}{exe} not found\n";my($u,$gid)=(stat $g->{dir}{exe})[4,5];defined$u or die"FATAL:stat failed\n";$g->{user}={uid=>$u,gid=>$gid}}; BEGIN{($g->{user}{uid}||$g->{user}{gid})&& do{use lib"$g->{dir}{path}/lib";require set_uuid;set_uuid::set_uuid($g->{user}{uid},$g->{user}{gid},1)||die"Failed to drop privileges: $!"}}; use lib $g->{dir}{path}.'/lib';my%seen;my@f=grep{my$b=$_;$b=~s{^.*/}{};!$seen{$b}++}(glob("$g->{dir}{lib}/*.pm"),glob("common_lib/*.pm"));my$e='';eval{for(@f){next unless -f$_&&/\.pm$/;open(my$h,'<',$_)or($e.="Can't open $_: $!\n",next);my$p=0;for(1..10){last unless defined(my$l=<$h>);$p=1,last if$l=~/^\s*package\s+\S+;/}close$h;if($p){(my$m=$_)=~s{^.*/}{};$m=~s/\.pm$//;$m=~s{/}{::}g;eval"require $m" or $e.="Error using $m: $@\n"}else{do$_ or $e.="Error in file $_:[".($@||"Make sure it evaluates to 'true'")."]\n"}}};$e.=$@ if$@;$e and print STDERR"\nCompilation failed:\n$e"and exit 1;undef $e;undef @f;undef %seen; package main; #### [loader done] ####;

use feature 'say';

use Log::Any::Adapter;     Log::Any::Adapter->set('Stderr');
use Fcntl qw(:DEFAULT :flock);

# ─── CPAN modules ──────────────────────────────────────────────────────────
use Crypt::PRNG                 qw(random_bytes);
use Crypt::Mac::HMAC            qw(hmac);
use Crypt::Digest::BLAKE2b_256  qw(blake2b_256);
use file_attr                   qw(get_file_attr set_file_attr del_file_attr);
use fast_file_hash             ();                # fast_file_hash::fast_file_hash
use read_write                 ();                # read_write::read / write

# ─── CONSTANTS ─────────────────────────────────────────────────────────────
use constant {
    MASTER_SIZE   => 64,                      # 512-bit master key
    MASTER_PATH   => '/root/master_64_x.bin',
    TAG_PREFIX    => 'TEAMLOCK-v2|',          # HMAC domain-separator
    XATTR_PREFIX  => '_gv_x_',                # HMAC tag attribute
    XATTR_CONFIG  => '_gv_c_',                # integrity-cfg attribute
};

# ─── INTEGRITY MAP & DEFAULTS ─────────────────────────────────────────────
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
my %ATTR_TO_CODE = reverse %CODE_MAP;


# -------- FIXED: build at run-time, not compile-time ----------------------
sub PARANOID () {                     # behaves like a constant
    state $P = { map { $_ => 1 } values %CODE_MAP };
    return $P;
}
# -------------------------------------------------------------------------


use constant MINIMAL  => {
    _full_path   => 1, _basename  => 1,
    _owner_uid   => 1, _group_gid => 1,
    _permissions => 1,
};

# ─── FILE-LEVEL DEFAULTS (new) ────────────────────────────────────────────
my %FILE_INTEGRITY_DEFAULTS = (
    # Hash-style example (leading underscore optional)
    '/tmp/hello_1.txt' => {
        device_id    => 0,
        inode        => 0,
        link_count   => 0,
        owner_uid    => 1,
        group_gid    => 1,
        permissions  => 1,
    },

    '/tmp/what_ever.txt' => MINIMAL,

    # Array-style (short-codes) also allowed:
    # '/var/lib/important.db' => [qw(fp bn di fh)],
);

# ─── TEAM TABLE ───────────────────────────────────────────────────────────
my %TEAMS = (
    db => {
        executable => '/usr/sbin/mysqld',
        integrity  => [qw(fp bn di in lc ou og pe em fh)],
        configs    => [
            { file => '/etc/my.cnf.d/server.cnf', integrity => [qw(fp bn di in lc ou og pe em fh)] },
            { file => '/etc/mysql.key',           integrity => { _full_path => 1, _basename => 1, _device_id => 1 } },
        ],
    },

    cat1 => {
        executable => '/usr/bin/cat',
        integrity  => PARANOID,
        configs    => [
            { file => '/tmp/hello_1.txt', integrity => [qw(fp bn di in lc ou og pe em fh)] },
            { file => '/tmp/hello_2.txt', integrity => [qw(fp bn di in lc ou og pe em fh)] },
            { file => '/etc/mysql.key',   integrity => [qw(fp bn di in lc ou og pe em fh)] },
            { file => '/tmp/what_ever.txt'                                                 },
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
);

# ───────────────────────────────────────────────────────────────────────────
main();
exit 0;

# ─── FUNCTIONS ────────────────────────────────────────────────────────────

sub main {
    my ($master, $err) = init_master(MASTER_PATH, MASTER_SIZE);
    $master // die "Cannot initialise MASTER key: $err";

    my $verify   = 1;
    my $register = 0;   # ← your original default

    for my $team (sort keys %TEAMS) {
        my $ref = $TEAMS{$team};
        my ($ok, $msg);

        if ($register) {
            say "Registering team “$team” → $ref->{executable}";
            ($ok, $msg) = register_team($team, $ref, $master);
            warn "$msg\n" if defined $msg && !$ok;
        }

        if ($verify) {
            ($ok, $msg) = verify_team($team, $ref, $master);
            warn "$msg\n" if defined $msg && !$ok;
        }
    }
}

# ─── Integrity helpers ────────────────────────────────────────────────────
sub _canon_attr {
    my ($k) = @_;
    $k = "_$k"          unless $k =~ /^_/;          # add leading _
    $k =~ s/^_+/_/;                                # collapse multiple _
    return $k;
}

#sub normalize_integrity_cfg {
#    my ($spec_in) = @_;
#
#    # Initialize a base config with all known attributes set to 0 (OFF).
#    # This ensures the returned hash is "dense", containing all attributes.
#    my %normalized_cfg;
#    for my $attr_name (values %CODE_MAP) {
#        $normalized_cfg{$attr_name} = 0;
#    }
#
#    # Determine the actual specification to apply. PARANOID is the ultimate default
#    # if $spec_in is undefined.
#    my $spec_to_apply = $spec_in // PARANOID;
#
#    if (ref $spec_to_apply eq 'HASH') {
#        # Apply the hash specification.
#        # Iterate through the provided spec and update %normalized_cfg.
#        while (my ($k, $v) = each %$spec_to_apply) {
#            my $attr = _canon_attr($k);
#            # Ensure we only act on known attributes (e.g., _full_path is a key in %ATTR_TO_CODE).
#            if (exists $ATTR_TO_CODE{$attr}) {
#                $normalized_cfg{$attr} = $v ? 1 : 0; # Set to 1 if $v is true, else 0.
#            }
#        }
#    }
#    elsif (ref $spec_to_apply eq 'ARRAY') {
#        # Apply the array specification (short codes like 'fp', 'bn').
#        for my $code (@$spec_to_apply) {
#            my $attr = $CODE_MAP{$code}; # Convert short code to attribute name (e.g., 'fp' to '_full_path').
#            if (defined $attr) { # Check if $code is a valid short code.
#                $normalized_cfg{$attr} = 1; # Turn this attribute ON.
#            }
#        }
#    }
#    # If $spec_to_apply was not a HASH or ARRAY (e.g., if PARANOID itself was misdefined,
#    # or $spec_in was an unsupported type and not undef), %normalized_cfg would remain
#    # as initialized (all attributes 0). This is unlikely given current constants.
#
#    return \%normalized_cfg;
#}

sub normalize_integrity_cfg {
    my ($spec) = @_;
    $spec //= PARANOID;

    if (ref $spec eq 'HASH') {
        my %cfg;
        while (my ($k, $v) = each %$spec) {
            next unless $v;
            my $attr = _canon_attr($k);
            $cfg{$attr} = 1 if exists $ATTR_TO_CODE{$attr};
        }
        return \%cfg;
    }
    elsif (ref $spec eq 'ARRAY') {
        my %cfg;
        for my $code (@$spec) {
            my $attr = $CODE_MAP{$code};
            $cfg{$attr} = 1 if defined $attr;
        }
        return \%cfg;
    }
    else {
        return { %{ PARANOID() } };
    }
}

sub __delete__encode_cfg_to_codes {
    my ($cfg) = @_;
    [ map { $ATTR_TO_CODE{$_} } grep { $cfg->{$_} } sort keys %$cfg ];
}

sub __delete__decode_codes_to_cfg {
    my ($codes) = @_;
    my %cfg; $cfg{$CODE_MAP{$_}} = 1 for @$codes;
    \%cfg;
}


sub encode_cfg_to_codes {
    my ($cfg) = @_;
    # include every attr, 1 if set, 0 if not
    my @codes;
    while (my ($code, $attr) = each %CODE_MAP) {
        push @codes, ($cfg->{$attr} ? $code : "!$code");
    }
    return \@codes;
}

sub decode_codes_to_cfg {
    my ($codes) = @_;
    # start with all off
    my %cfg = map { $CODE_MAP{$_} => 0 } keys %CODE_MAP;
    for my $token (@$codes) {
        if ($token =~ /^!(.+)$/) {
            # explicit zero, no-op
        }
        else {
            my $attr = $CODE_MAP{$token};
            $cfg{$attr} = 1 if defined $attr;
        }
    }
    return \%cfg;
}

sub choose_cfg {   # precedence: override → file-defaults → PARANOID
    my ($file, $override) = @_;
    return normalize_integrity_cfg($override)                          if defined $override;
    return normalize_integrity_cfg($FILE_INTEGRITY_DEFAULTS{$file})    if exists $FILE_INTEGRITY_DEFAULTS{$file};
    return { %{ PARANOID() } };
}

# ─── fast_file_hash thin wrapper ──────────────────────────────────────────
sub file_hash { 
    my ( $file, $cfg ) = @_;
    my $ret = fast_file_hash::fast_file_hash($file, $cfg) ;
    return $ret;
}

# ─── xattr helpers ────────────────────────────────────────────────────────
sub store_cfg_attr {
    my ($file, $team, $cfg) = @_;
    set_file_attr($file, XATTR_CONFIG . ".$team", encode_cfg_to_codes($cfg));
}

sub load_cfg_attr {
    my ($file, $team) = @_;
    my $raw = get_file_attr($file, XATTR_CONFIG . ".$team") or return;
    return decode_codes_to_cfg($raw) if ref $raw eq 'ARRAY';
    return normalize_integrity_cfg($raw) if ref $raw eq 'HASH';
    return;
}

# ─── Registration ─────────────────────────────────────────────────────────
# ─── Registration ─────────────────────────────────────────────────────────
sub register_team {
    my ($key, $team, $master) = @_;

    my $exe = $team->{executable}
      or return (undef, "[register:$key] no executable");
    return (undef, "[register:$key] exe not readable: $exe") unless -r $exe;

    # determine and persist the exe’s integrity spec
    my $exe_cfg = choose_cfg($exe, $team->{integrity});
    store_cfg_attr($exe, $key, $exe_cfg)
      or return (undef, "[register:$key] failed to store exe cfg");

    my $data = TAG_PREFIX . file_hash($exe, $exe_cfg);

    my $configs = $team->{configs}
      or return (undef, "[register:$key] no config files");

    for my $entry (@$configs) {
        my $file = $entry->{file}
          or return (undef, "[register:$key] config entry missing 'file'");
        return (undef, "[register:$key] cfg not readable: $file") unless -r $file;

        my $cfg = choose_cfg($file, $entry->{integrity});
        store_cfg_attr($file, $key, $cfg)
          or return (undef, "[register:$key] failed to store cfg for $file");

        $data .= file_hash($file, $cfg);
    }

    my $Ki  = hmac('BLAKE2b_256', $master, "TEAM-$key");
    my $tag = hmac('BLAKE2b_256', $Ki,     $data);

    set_file_attr($exe, XATTR_PREFIX . ".$key", $tag)
      or return (undef, "[register:$key] failed to set exe tag");

    say "[register:$key] OK.";
    return (1, '');
}

sub __old__register_team {
    my ($key, $team, $master) = @_;

    my $exe = $team->{executable} or die "[register:$key] no executable";
    die "[register:$key] exe unreadable" unless -r $exe;

    my $exe_cfg = choose_cfg($exe, $team->{integrity});
    store_cfg_attr($exe, $key, $exe_cfg);

    my $data = TAG_PREFIX . file_hash($exe, $exe_cfg);

    for my $c (@{ $team->{configs} // []}) {
        my $file = $c->{file} or die "[register:$key] config entry missing file";
        die "[register:$key] unreadable: $file" unless -r $file;

        my $cfg = choose_cfg($file, $c->{integrity});
        store_cfg_attr($file, $key, $cfg);
        $data .= file_hash($file, $cfg);
    }

    my $Ki  = hmac('BLAKE2b_256', $master, "TEAM-$key");
    my $tag = hmac('BLAKE2b_256', $Ki,     $data);
    set_file_attr($exe, XATTR_PREFIX . ".$key", $tag);
    say "[register:$key] OK";
}

# ─── Verification ─────────────────────────────────────────────────────────
# ─── Verification ─────────────────────────────────────────────────────────
# ─── Verification ─────────────────────────────────────────────────────────
sub verify_team {
    my ($key, $team, $master) = @_;

    my $exe = $team->{executable}
      or return (undef, "[verify:$key] no executable");

    # MUST have stored cfg attr for executable
    my $exe_cfg = load_cfg_attr($exe, $key)
      or return (undef, "[verify:$key] missing cfg attr for exe $exe");

    # MUST have stored tag
    my $tag = get_file_attr($exe, XATTR_PREFIX . ".$key")
      or return (undef, "[verify:$key] missing exe tag");

    my $Ki   = hmac('BLAKE2b_256', $master, "TEAM-$key");
    my $data = TAG_PREFIX . file_hash($exe, $exe_cfg);

    my $configs = $team->{configs}
      or return (undef, "[verify:$key] no config files");

    for my $entry (@$configs) {
        my $file = $entry->{file}
          or return (undef, "[verify:$key] config entry missing 'file'");

        # MUST have stored cfg attr for this config file
        my $cfg = load_cfg_attr($file, $key)
          or return (undef, "[verify:$key] missing cfg attr for $file");

        return (undef, "[verify:$key] cfg not readable: $file") unless -r $file;

        $data .= file_hash($file, $cfg);
    }

    my $candidate = hmac('BLAKE2b_256', $Ki, $data);
    return (undef, "[verify:$key] FAILED for $exe")
      unless secure_bcmp($candidate, $tag);

    say "[verify:$key] OK.";
    return (1, '');
}

sub ___old_verify_team {
    my ($key, $team, $master) = @_;

    my $exe = $team->{executable} or die "[verify:$key] no executable";
    my $exe_cfg = load_cfg_attr($exe, $key) // choose_cfg($exe, $team->{integrity});

    my $tag = get_file_attr($exe, XATTR_PREFIX . ".$key")
      or die "[verify:$key] missing tag";

    my $data = TAG_PREFIX . file_hash($exe, $exe_cfg);

    for my $c (@{ $team->{configs} // []}) {
        my $file = $c->{file} or die "[verify:$key] config entry missing file";
        my $cfg  = load_cfg_attr($file, $key) // choose_cfg($file, $c->{integrity});
        $data .= file_hash($file, $cfg);
    }

    my $Ki  = hmac('BLAKE2b_256', $master, "TEAM-$key");
    my $cmp = hmac('BLAKE2b_256', $Ki,     $data);
    die "[verify:$key] FAILED" unless secure_bcmp($cmp, $tag);
    say "[verify:$key] OK";
}

# ─── Master key handling ──────────────────────────────────────────────────
sub init_master {
    my ($path, $size) = @_;
    unless (-e $path) {
        read_write::write($path, random_bytes($size)) or die "create $path: $!";
        chmod 0400, $path                             or die "chmod $path: $!";
        say "Generated new $size-byte MASTER key at $path";
    }
    my $m = read_write::read($path);
    die "MASTER wrong length" unless defined $m && length($m) == $size;
    return $m;
}

# ─── Constant-time compare ────────────────────────────────────────────────
sub secure_bcmp {
    my ($a,$b)=@_;
    return unless defined $a && defined $b && length($a)==length($b);
    my $d=0; $d|=(ord substr($a,$_,1))^(ord substr($b,$_,1)) for 0..length($a)-1;
    !$d;
}

