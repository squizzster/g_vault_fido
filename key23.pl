#!/usr/bin/env perl

#######  [v1.0 loader]  ########
use v5.14; use strict;use warnings;use utf8;binmode(STDIN,':encoding(UTF-8)');binmode(STDOUT,':encoding(UTF-8)');binmode(STDERR,':encoding(UTF-8)');$|=1;my$g;use FindBin qw($RealBin $RealScript);BEGIN{$g->{dir}={exe=>"$RealBin/$RealScript",path=>$RealBin,lib=>"$RealBin/lib",conf=>"$RealBin/conf"};-r$g->{dir}{exe}or die"FATAL:$g->{dir}{exe} not found\n";my($u,$gid)=(stat $g->{dir}{exe})[4,5];defined$u or die"FATAL:stat failed\n";$g->{user}={uid=>$u,gid=>$gid}}; BEGIN{($g->{user}{uid}||$g->{user}{gid})&& do{use lib"$g->{dir}{path}/lib";require set_uuid;set_uuid::set_uuid($g->{user}{uid},$g->{user}{gid},1)||die"Failed to drop privileges: $!"}}; use lib $g->{dir}{path}.'/lib';my%seen;my@f=grep{my$b=$_;$b=~s{^.*/}{};!$seen{$b}++}(glob("$g->{dir}{lib}/*.pm"),glob("common_lib/*.pm"));my$e='';eval{for(@f){next unless -f$_&&/\.pm$/;open(my$h,'<',$_)or($e.="Can't open $_: $!\n",next);my$p=0;for(1..10){last unless defined(my$l=<$h>);$p=1,last if$l=~/^\s*package\s+\S+;/}close$h;if($p){(my$m=$_)=~s{^.*/}{};$m=~s/\.pm$//;$m=~s{/}{::}g;eval"require $m" or $e.="Error using $m: $@\n"}else{do$_ or $e.="Error in file $_:[".($@||"Make sure it evaluates to 'true'")."]\n"}}};$e.=$@ if$@;$e and print STDERR"\nCompilation failed:\n$e"and exit 1;undef $e;undef @f;undef %seen; package main; #### [loader done] ####;

#  “Trust only what was registered and stored.”

use feature 'say';
use Log::Any::Adapter;     Log::Any::Adapter->set('Stderr');
use Fcntl qw(:DEFAULT :flock);
use File::ExtAttr ();
use Cwd  qw(abs_path);
use File::FnMatch qw(:fnmatch);

# ─── CONSTANTS ────────────────────────────────────────────────────────────
use constant {
    MASTER_SIZE  => 64,
    MASTER_PATH  => '/tmp/master_64_x.bin',

    TAG_PREFIX   => 'TEAMLOCK-v1|',
    XATTR_TEAM   => '_gv_',          # ← single attribute per-team

    PATH_SEP     => "\0",
};

# Bit-position for every 2-letter integrity code
my %CODE_TO_BIT = (
    fp => 0, bn => 1, di => 2, in => 3, lc => 4,
    ou => 5, og => 6, pe => 7, em => 8, fh => 9,
);
my @BIT_TO_CODE = sort { $CODE_TO_BIT{$a} <=> $CODE_TO_BIT{$b} } keys %CODE_TO_BIT;

# ─── DEBUG helper ─────────────────────────────────────────────────────────
use constant DEBUG => ($ENV{TEAMLOCK_DEBUG}//1);
sub D { return unless DEBUG; print STDERR "[DEBUG] ", @_, "\n" }

# ─── CPAN modules ─────────────────────────────────────────────────────────
use Crypt::PRNG                qw(random_bytes);
use Crypt::Mac::HMAC           qw(hmac);
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256);
use file_attr                  qw(get_file_attr set_file_attr);
use fast_file_hash             ();
use read_write                 ();

# ─── DATA TABLES (unchanged) ──────────────────────────────────────────────
my %CODE_MAP = (
    fp => '_full_path',  bn => '_basename',   di => '_device_id',
    in => '_inode',      lc => '_link_count', ou => '_owner_uid',
    og => '_group_gid',  pe => '_permissions',em => '_epoch_modify',
    fh => '_file_hash'
);
my %ATTR_TO_CODE = reverse %CODE_MAP;

sub BASENAME_ONLY   () { state $C = { _basename => 1 }; $C }
sub PATH_PERMS      () { state $C = {
    _full_path   => 1, _basename    => 1,
    _owner_uid   => 1, _group_gid   => 1, _permissions => 1,
}; $C }
sub INODE_PERMS     () { state $C = {
    _device_id   => 1, _inode       => 1, _link_count  => 1,
    _full_path   => 1, _basename    => 1,
    _owner_uid   => 1, _group_gid   => 1, _permissions => 1,
}; $C }
sub CONTENT_PERMS   () { state $C = {
    _full_path   => 1, _basename    => 1,
    _owner_uid   => 1, _group_gid   => 1, _permissions => 1,
    _file_hash   => 1,
}; $C }
sub CONTENT_ONLY    () { state $C = { _file_hash => 1 }; $C }
sub FORENSIC_FREEZE () { state $C = { map { $_ => 1 } values %CODE_MAP }; $C }

# ─── FILE DEFINITIONS ─────────────────────────────────────────────────────
my %FILES = (
    'mysql_server'      => [ '/usr/sbin/mysqld', 'CONTENT_ONLY' ],
    '/usr/sbin/mysqld'                        => FORENSIC_FREEZE,
    '/usr/bin/cat'                            => PATH_PERMS,
    '/usr/sbin/init'                          => INODE_PERMS,
    '/tmp/change_me'                          => CONTENT_ONLY,
);

# ─── TEAM DEFINITIONS ─────────────────────────────────────────────────────
my %TEAMS = (
    db => {
        pid        => 'mysql_server',
        uid        => [10001, 0, 100],
        gid        => [10001, 0, 100],
        ppid       => '/tmp/change_me',
        walk_back  => 1,
        configs    => [
            '/etc/my.cnf.d/*l*.cnf',
            '/etc/mysql.key',
        ],
    },
    cat1 => {
        pid     => '/usr/sbin/mysqld',
        gid     => [10001, 100],
        configs => [
            '/tmp/hello_?.txt',
            '/etc/mysql.key',
            '/tmp/what_ever.txt',
            '~/*.cfg',
        ],
    },
    cat2 => {
        pid     => '/usr/bin/cat',
        ppid    => 'mysql_server',
        configs => [
            '/tmp/hello_again.txt',
            '/etc/mysql.key',
            '/home/marko/x.txt',
        ],
    },
);

# ╔════════════════════════════════════════════════════════════════════════╗
# ║  PUBLIC WRAPPERS  (drop-in originals) – delegate to private helpers   ║
# ╚════════════════════════════════════════════════════════════════════════╝

sub main                     { _en_main(@_) }
sub register_team            { _rt_register(@_) }
sub verify_team              { _vt_verify(@_) }
sub verify_exe_config        { _vx_verify_exe_config(@_) }
sub verify_linkage           { _vl_verify_linkage(@_) }

# ——— Unchanged "helper" functions copied verbatim below ———

sub normalize_integrity_cfg {
    my ($s) = @_;
    $s //= FORENSIC_FREEZE;
    if (ref $s eq 'HASH') {
        my %o;
        while (my ($k, $v) = each %$s) {
            next unless $v;
            $k = "_$k" unless $k =~ /^_/;
            $k =~ s/^_+/_/;
            $o{$k} = 1 if $ATTR_TO_CODE{$k};
        }
        return \%o;
    }
    elsif (ref $s eq 'ARRAY') {
        my %o;
        for (@$s) { my $a = $CODE_MAP{$_}; $o{$a} = 1 if $a }
        return \%o;
    }
    { %{FORENSIC_FREEZE()} }
}
sub encode_cfg_to_codes {
    my ($c) = @_;
    [ grep { $c->{ $CODE_MAP{$_} } } sort keys %CODE_MAP ]
}
my %_DECODE_CACHE;
sub decode_codes_to_cfg_cached {
    my ($arr) = @_;
    return $_DECODE_CACHE{join ',', @$arr} if $_DECODE_CACHE{join ',', @$arr};
    my %h = map { $CODE_MAP{$_} => 0 } keys %CODE_MAP;
    for (@$arr) { /^!/ && next; $h{ $CODE_MAP{$_} } = 1 for @$arr }
    $_DECODE_CACHE{join ',', @$arr} = \%h;
}
sub decode_codes_to_cfg { decode_codes_to_cfg_cached($_[0]) }
sub file_hash  { fast_file_hash::fast_file_hash(@_) }
sub _attr          { $_[0] . '.' . $_[1] }
sub store_team_attr { set_file_attr(@_)     }
sub load_team_attr  { get_file_attr(@_)     }
sub _canon_cfg_pattern {
    my ($pat) = @_;
    return ($pat =~ /[\*\?\[]/)        # keep globs (incl. '~') verbatim
         ? $pat
         : (abs_path($pat) || $pat);   # absolute path for literals only
}
sub list_teams {
    my ($exe) = @_;
    grep { get_file_attr($exe, _attr(XATTR_TEAM, $_)) } keys %TEAMS;
}
sub _cfg_match {
    my ($patterns, $file) = @_;
    my $file_uid  = (stat $file)[4] // undef;
    my $file_home = defined $file_uid ? (getpwuid($file_uid))[7] : undef;
    for my $pat (@$patterns) {
        my $p = $pat;
        if ($p =~ m{^~([^/]*)/?(.*)}) {
            my ($user, $rest) = ($1, $2 // '');
            my $home;
            if ($user eq '') { $home = $file_home; }
            else { $home = (getpwnam($user))[7]; }
            next unless defined $home && length $home;
            $p = $home . '/' . $rest;
        }
        return 1 if fnmatch($p, $file, FNM_PATHNAME | FNM_PERIOD);
    }
    return 0;
}
sub _pack_spec_bits   { my $bits = 0; $bits |= 1 << $CODE_TO_BIT{$_} for @{$_[0]}; $bits }
sub _unpack_spec_bits {
    my ($bits) = @_;
    return [ sort map { $BIT_TO_CODE[$_] } grep { $bits & (1 << $_) } 0 .. $#BIT_TO_CODE ];
}
sub _compact_meta {
    my ($m) = @_;
    my %c = (
        v => 1,
        s => _pack_spec_bits($m->{spec}),
        p => join("\0", @{ $m->{patterns} // [] }),
        t => $m->{tag},
    );
    $c{u} = join(',', @{ $m->{uid} }) if $m->{uid};
    $c{g} = join(',', @{ $m->{gid} }) if $m->{gid};
    $c{w} = 1                         if $m->{walk_back};
    if (my $pp = $m->{ppid}) {
        $c{P} = $pp->{path};
        $c{S} = _pack_spec_bits($pp->{spec});
        $c{H} = $pp->{hash};
    }
    \%c
}
sub _expand_meta {
    my ($c) = @_;
    my %m = (
        v        => 1,
        spec     => _unpack_spec_bits($c->{s}),
        patterns => [ split /\0/, ($c->{p} // '') ],
        tag      => $c->{t},
    );
    $m{uid}       = [ split /,/, $c->{u} ] if exists $c->{u};
    $m{gid}       = [ split /,/, $c->{g} ] if exists $c->{g};
    $m{walk_back} = 1                      if exists $c->{w};
    if (exists $c->{P}) {
        $m{ppid} = {
            path => $c->{P},
            spec => _unpack_spec_bits($c->{S}),
            hash => $c->{H},
        };
    }
    \%m
}
sub _store_team_attr_compact {
    my ($file, $key, $meta) = @_;
    store_team_attr($file, $key, _compact_meta($meta));
}
sub _load_team_attr_compact {
    my ($file, $key) = @_;
    my $c = load_team_attr($file, $key) or return;
    _expand_meta($c);
}

# ╭───────────────────────── ENTRY POINT WRAPPER ─────────────────────────╮
sub _en_main {
    my $register = 1;
    my $verify   = 1;

    my ($master, $err) = init_master(MASTER_PATH, MASTER_SIZE);
    $master // die "Cannot initialise MASTER key: $err";

    for my $team (sort keys %TEAMS) {
        print "REGISTER [$team]\n" if $register;
        _rt_register($team, $TEAMS{$team}, $master) if $register;

        print "VERIFY   [$team]\n" if $verify;
        _vt_verify($team, $master) if $verify;
    }

    _vl_verify_linkage();
    return 1;
}

sub _rt_is_readable { -r $_[0] }
sub _rt_log_unreadable {
    my ($team, $exe) = @_;
    D "[register:$team] pid unreadable $exe";
    return;
}

sub _rt_generate_tag {
    my ($team, $meta, $master) = @_;
    my $Ki  = hmac('BLAKE2b_256', $master, "TEAM-$team");
    my $crc = g_checksum::checksum_data_v2($meta);
    return hmac('BLAKE2b_256', $Ki, TAG_PREFIX . $crc);
}

sub _vt_refresh_ppid_hash {
    my ($pp) = @_;
    my $pp_path = $pp->{path} // return;
    if (-r $pp_path) {
        my $dec = decode_codes_to_cfg($pp->{spec});
        $pp->{hash} = file_hash($pp_path, $dec);
    } else {
        $pp->{hash} = '';
    }
}

# ╭──────────────────── LINKAGE VERIFICATION MATRIX  ─────────╮
sub _vl_verify_linkage {
    my @rows = _vl_gather_rows();
    return unless @rows;
    my @hdrs   = _vl_table_headers();
    my @widths = _vl_calc_widths(\@hdrs, \@rows);
    my $fmt    = join(' | ', map { "%-*s" } @hdrs ) . "\n";
    my $sep    = '-' x (_vl_sum(@widths) + 3 * (@hdrs - 1));
    say "\n=== Linkage Verification Matrix ===";
    printf $fmt, map { ($widths[$_], $hdrs[$_]) } 0..$#hdrs;
    say $sep;
    for my $r (@rows) {
        printf $fmt, map { ($widths[$_], $r->[$_]) } 0..$#hdrs;
    }
    say $sep;
}
sub _vl_table_headers {
    return qw(
        Team PID PID_SpecName PPID PPID_SpecName UIDs GIDs WalkBack
        Permissions Spec Config Exists Readable Result
    );
}
sub _vl_build_spec_name_map {
    my %map;
    for my $name (qw(
        BASENAME_ONLY PATH_PERMS INODE_PERMS CONTENT_PERMS
        CONTENT_ONLY FORENSIC_FREEZE
    )) {
        no strict 'refs';
        my $dec   = &{$name}();
        my $codes = encode_cfg_to_codes($dec);
        $map{ join(',', @$codes) } = $name;
    }
    return \%map;
}
sub _vl_ppid_columns {
    my ($pp, $map) = @_;
    return ('', '') unless $pp;
    my $raw  = $pp->{path} // '';
    my $path = $raw ? "$raw [i]" : '';
    my $name = $pp->{spec} ? ($map->{ join(',', @{ $pp->{spec} }) } // 'CUSTOM') : '';
    return ($path, $name);
}
sub _vl_row {
    my ($team,$exe,$pid_spec,$pp_path,$pp_spec,$uid_list,$gid_list,$walk,$spec,$cfg)=@_;
    my $exists   = -e $cfg ? 'yes' : 'no';
    my $readable = -r $cfg ? 'yes' : 'no';
    my $perms    = sprintf "%04o", ((stat($cfg))[2] // 0) & 07777;
    my $result   = ($exists eq 'yes' && $readable eq 'yes' && _vx_verify_exe_config($exe, $cfg))
                 ? '✓' : '✗';
    return [
        $team,           # Team
        $exe,            # PID
        $pid_spec,       # PID_SpecName
        $pp_path,        # PPID
        $pp_spec,        # PPID_SpecName
        $uid_list,       # UIDs
        $gid_list,       # GIDs
        $walk,           # WalkBack
        $perms,          # Permissions
        join(',', @$spec),# Spec (codes)
        $cfg,            # Config
        $exists,         # Exists
        $readable,       # Readable
        $result,         # Result
    ];
}
sub _vl_calc_widths {
    my ($hdrs, $rows) = @_;
    my @w = map { length $_ } @$hdrs;
    for my $r (@$rows) {
        for my $i (0 .. $#$r) {
            my $l = length $r->[$i];
            $w[$i] = $l if $l > $w[$i];
        }
    }
    return @w;
}
sub _vl_sum { my $s = 0; $s += $_ for @_; return $s }

# ╭──────────────────── MASTER KEY & CRYPTO HELPERS (unchanged) ──────────╮
sub init_master {
    my ($path,$size)=@_;
    unless(-e $path){
        read_write::write($path, random_bytes($size)) or die "create $path: $!";
        chmod 0400, $path or die "chmod $path: $!";
        say "Generated new master key at $path";
    }
    my $m=read_write::read($path);
    die "Master wrong length" unless defined $m && length($m)==$size;
    $m;
}

sub bcmp {
    my ($a, $b) = @_;
    return unless defined $a && defined $b && length($a)==length($b);
    return unless $a eq $b;
    return 1;
}

sub secure_bcmp {
    my ($a, $b) = @_;

    return unless defined $a && defined $b && length($a)==length($b);

    my $d = 0;
    $d |= ord(substr($a, $_, 1)) ^ ord(substr($b, $_, 1)) for 0 .. length($a) - 1;

    return $d ? undef : 1;
}

# ─── NEW HELPERS ──────────────────────────────────────────────────────────
sub _spec_to_dec {
    # Convert whatever the caller gave (HASH, CODEREF, constant name, undef)
    # into a *normalised* integrity-config HASH.
    my ($spec) = @_;
    my $dec;
    if   (!defined $spec)          { $dec = FORENSIC_FREEZE() }
    elsif (ref $spec eq 'HASH')    { $dec = $spec }
    elsif (ref $spec eq 'CODE')    { $dec = $spec->() }
    elsif (!ref $spec) {                           # constant / sub name
        no strict 'refs';
        die "Unknown integrity spec '$spec'" unless defined &{$spec};
        $dec = &{$spec}();
    }
    else { die "Unsupported integrity-spec type" }
    return normalize_integrity_cfg($dec);
}

sub _lookup_file {
    my ($name) = @_;

    # 1) direct lookup by key (label, '/' path, or literal '~' path)
    if (exists $FILES{$name}) {
        my $val = $FILES{$name};
        if (ref $val eq 'ARRAY') {
            my ($p, $s) = @$val;
            return ($p, _spec_to_dec($s));
        }
        return ($name, _spec_to_dec($val));
    }

    # 2) tilde-expansion lookup: if the caller passed "~/..." or "~user/..."
    if ($name =~ /^~[A-Za-z0-9_-]*\//) {
        my $expanded = glob($name);
        if ($expanded) {
            # 2a) see if the expanded path is itself a FILES key
            if (exists $FILES{$expanded}) {
                my $v = $FILES{$expanded};
                return ($expanded, _spec_to_dec(ref $v eq 'ARRAY' ? $v->[1] : $v));
            }
            # 2b) fall-through to treat it as a literal path below:
            $name = $expanded;
        }
    }

    # 3) reverse-lookup for array-style entries if they stored this path
    if ($name =~ m{^/}) {
        for my $val (values %FILES) {
            next unless ref $val eq 'ARRAY';
            my ($p, $s) = @$val;
            return ($p, _spec_to_dec($s)) if $p eq $name;
        }
    }

    # not found
    return;
}

# ─── MODIFIED CORE ROUTINES ──────────────────────────────────────────────
sub choose_cfg {
    my ($id) = @_;
    my (undef, $dec) = _lookup_file($id);
    return $dec // FORENSIC_FREEZE();
}

sub _rt_register {
    my ($team, $def, $master) = @_;
    my $exe_id = $def->{pid} or return;

    my ($exe_path) = _lookup_file($exe_id)
        or return _rt_log_unreadable($team, $exe_id);

    return _rt_log_unreadable($team, $exe_path) unless -r $exe_path;

    my $meta = _rt_build_meta($team, $def, $exe_id);
    $meta->{tag} = _rt_generate_tag($team, $meta, $master);

    _store_team_attr_compact($exe_path, _attr(XATTR_TEAM, $team), $meta)
        or D "[register:$team] failed store_team_attr";
    D "[register:$team] OK";
    return 1;
}

sub _rt_build_meta {
    my ($team, $def, $exe_id) = @_;
    my (undef, $exe_dec) = _lookup_file($exe_id);

    my $pp_meta   = _rt_build_ppid_block($def->{ppid});
    my @patterns  = map { _canon_cfg_pattern($_) } @{ $def->{configs} // [] };
    @patterns     = sort @patterns;

    my %meta = (
        v        => 1,
        spec     => encode_cfg_to_codes($exe_dec),
        patterns => \@patterns,
    );
    $meta{ppid}      = $pp_meta          if $pp_meta;
    $meta{uid}       = $def->{uid}       if $def->{uid};
    $meta{gid}       = $def->{gid}       if $def->{gid};
    $meta{walk_back} = $def->{walk_back} if exists $def->{walk_back};
    return \%meta;
}

sub _rt_build_ppid_block {
    my ($pp_id) = @_;
    return unless $pp_id;

    my ($pp_path, $pp_dec) = _lookup_file($pp_id) or return;
    return unless -r $pp_path;

    return {
        path => $pp_path,
        spec => encode_cfg_to_codes($pp_dec),
        hash => file_hash($pp_path, $pp_dec),
    };
}

sub _vt_verify {
    my ($team, $master) = @_;
    my ($exe_path) = _lookup_file($TEAMS{$team}{pid})
        or do { D "[verify:$team] unknown executable"; return };

    my $meta = _load_team_attr_compact($exe_path, _attr(XATTR_TEAM, $team))
        or do { D "[verify:$team] missing team attr"; return };
    my $tag  = delete $meta->{tag};

    _vt_refresh_ppid_hash($meta->{ppid}) if $meta->{ppid};

    my $Ki  = hmac('BLAKE2b_256', $master, "TEAM-$team");
    my $crc = g_checksum::checksum_data_v2($meta);
    my $cmp = hmac('BLAKE2b_256', $Ki, TAG_PREFIX . $crc);

    unless (bcmp($cmp, $tag)) {
        D "[verify:$team] tag mismatch";
        return;
    }
    D "[verify:$team] OK";
    return 1;
}

sub _vx_verify_exe_config {
    my ($exe_id, $cfg) = @_;
    my ($exe_path) = _lookup_file($exe_id) or return;
    return unless -r $exe_path && -r $cfg;

    my $abs_cfg = abs_path($cfg) or return;
    my $master  = read_write::read(MASTER_PATH);
    return unless defined $master && length($master) == MASTER_SIZE;

    for my $team (list_teams($exe_path)) {
        my $meta = _load_team_attr_compact($exe_path, _attr(XATTR_TEAM, $team)) or next;
        next unless _cfg_match($meta->{patterns}, $abs_cfg);
        my $tag = delete $meta->{tag};
        _vt_refresh_ppid_hash($meta->{ppid}) if $meta->{ppid};
        my $cmp = hmac(
            'BLAKE2b_256',
            hmac('BLAKE2b_256', $master, "TEAM-$team"),
            TAG_PREFIX . g_checksum::checksum_data_v2($meta)
        );
        return 1 if $cmp eq $tag;
    }
    return;
}

sub _vl_gather_rows {
    my @rows;
    my $spec_map = _vl_build_spec_name_map();

    for my $team (sort keys %TEAMS) {
        my ($exe_path) = _lookup_file($TEAMS{$team}{pid}) or next;

        my $meta = _load_team_attr_compact($exe_path, _attr(XATTR_TEAM, $team)) or next;
        my ($pp_path, $pp_spec_name) = _vl_ppid_columns($meta->{ppid}, $spec_map);

        my $pid_spec_name = $spec_map->{ join(',', @{ $meta->{spec} }) } // 'CUSTOM';
        my $uid_list      = @{ $meta->{uid} // [] } ? join(',', @{ $meta->{uid} }) : '';
        my $gid_list      = @{ $meta->{gid} // [] } ? join(',', @{ $meta->{gid} }) : '';
        my $walk          = $TEAMS{$team}{walk_back} ? 'yes' : 'no';

        for my $pat (@{ $meta->{patterns} }) {
            my @matches = ($pat =~ /[\*\?\[]/) ? map { abs_path($_) } glob($pat) : ($pat);
            @matches = ('<none matched>') unless @matches;
            for my $cfg (@matches) {
                push @rows, _vl_row(
                    $team, $exe_path, $pid_spec_name, $pp_path, $pp_spec_name,
                    $uid_list, $gid_list, $walk, $meta->{spec}, $cfg
                );
            }
        }
    }
    return @rows;
}

# ================== END ==================
main();
1;

