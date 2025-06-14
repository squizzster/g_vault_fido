#!/usr/bin/env perl

#######  [v1.0 loader]  ########
use v5.14; use strict;use warnings;use utf8;binmode(STDIN,':encoding(UTF-8)');binmode(STDOUT,':encoding(UTF-8)');binmode(STDERR,':encoding(UTF-8)');$|=1;my$g;use FindBin qw($RealBin $RealScript);BEGIN{$g->{dir}={exe=>"$RealBin/$RealScript",path=>$RealBin,lib=>"$RealBin/lib",conf=>"$RealBin/conf"};-r$g->{dir}{exe}or die"FATAL:$g->{dir}{exe} not found\n";my($u,$gid)=(stat $g->{dir}{exe})[4,5];defined$u or die"FATAL:stat failed\n";$g->{user}={uid=>$u,gid=>$gid}}; BEGIN{($g->{user}{uid}||$g->{user}{gid})&& do{use lib"$g->{dir}{path}/lib";require set_uuid;set_uuid::set_uuid($g->{user}{uid},$g->{user}{gid},1)||die"Failed to drop privileges: $!"}}; use lib $g->{dir}{path}.'/lib';my%seen;my@f=grep{my$b=$_;$b=~s{^.*/}{};!$seen{$b}++}(glob("$g->{dir}{lib}/*.pm"),glob("common_lib/*.pm"));my$e='';eval{for(@f){next unless -f$_&&/\.pm$/;open(my$h,'<',$_)or($e.="Can't open $_: $!\n",next);my$p=0;for(1..10){last unless defined(my$l=<$h>);$p=1,last if$l=~/^\s*package\s+\S+;/}close$h;if($p){(my$m=$_)=~s{^.*/}{};$m=~s/\.pm$//;$m=~s{/}{::}g;eval"require $m" or $e.="Error using $m: $@\n"}else{do$_ or $e.="Error in file $_:[".($@||"Make sure it evaluates to 'true'")."]\n"}}};$e.=$@ if$@;$e and print STDERR"\nCompilation failed:\n$e"and exit 1;undef $e;undef @f;undef %seen; package main; #### [loader done] ####;

use strict;
use warnings;
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

    TAG_PREFIX   => 'TEAMLOCK-v3|',
    XATTR_TEAM   => '_gv_',          # ← single attribute per-team

    PATH_SEP     => "\0",
};

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

sub RENAME_ONLY      () { state $C = { _basename => 1 }; $C }

sub LOCATION_STATIC  () { state $C = {
    _full_path   => 1, _basename    => 1,
    _owner_uid   => 1, _group_gid   => 1, _permissions => 1,
}; $C }

sub FIXED_INODE_META () { state $C = {
    _device_id   => 1, _inode       => 1, _link_count  => 1,
    _full_path   => 1, _basename    => 1,
    _owner_uid   => 1, _group_gid   => 1, _permissions => 1,
}; $C }

sub CONTENT_STATIC   () { state $C = {
    _full_path   => 1, _basename    => 1,
    _owner_uid   => 1, _group_gid   => 1, _permissions => 1,
    _file_hash   => 1,
}; $C }

sub HASH_ROAMER      () { state $C = { _file_hash => 1 }; $C }

sub FORENSIC_FREEZE  () { state $C = { map { $_ => 1 } values %CODE_MAP }; $C }



# ─── FILE DEFINITIONS ─────────────────────────────────────────────────────
my %FILES = (
    '/usr/sbin/mysqld' => RENAME_ONLY,
    '/usr/bin/cat'     => LOCATION_STATIC,
    '/usr/sbin/init'   => FIXED_INODE_META,
    '/tmp/change_me'   => FORENSIC_FREEZE,
);

# ─── TEAM DEFINITIONS ─────────────────────────────────────────────────────
my %TEAMS = (
    db => {
        pid        => '/usr/sbin/mysqld',
        ppid       => '/tmp/change_me',
        walk_back  => 1,
        uid        => [10001, 0, 100],
        configs    => [
            '/etc/my.cnf.d/*l*.cnf',
            '/etc/mysql.key',
        ],
    },
    cat1 => {
        pid     => '/usr/bin/cat',
        configs => [
            '/tmp/hello_?.txt',
            '/etc/mysql.key',
            '/tmp/what_ever.txt',
            '~/*.cfg',
        ],
    },
    cat2 => {
        pid     => '/usr/bin/cat',
        ppid    => '/usr/sbin/init',
        configs => [
            '/tmp/hello_again.txt',
            '/etc/mysql.key',
            '/home/marko/x.txt',
        ],
    },
);

# ──────────────────────────────────────────────────────────────────────────
main();
exit 0;

# ══════════════════════════════════════════════════════════════════════════
# ─── DRIVER ───────────────────────────────────────────────────────────────
sub main {
    my ($master, $err) = init_master(MASTER_PATH, MASTER_SIZE);
    $master // die "Cannot initialise MASTER key: $err";

    my $register = 0;   # flip when you need fresh tags
    my $verify   = 1;
    for my $team (sort keys %TEAMS) {

        print "REGISTER [$team]\n" if $register;
        register_team($team, $TEAMS{$team}, $master) if $register;

        print "VERIFY   [$team]\n" if $verify;
        verify_team($team, $master) if $verify;

    }

    verify_linkage();
}

# ══════════════════════════════════════════════════════════════════════════
# ─── Integrity helpers ────────────────────────────────────────────────────
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
sub encode_cfg_to_codes { my ($c) = @_; [ map { $c->{$CODE_MAP{$_}} ? $_ : "!$_" } sort keys %CODE_MAP ] }
sub decode_codes_to_cfg { decode_codes_to_cfg_cached($_[0]) }

# cache decoder to save a little time
my %_DECODE_CACHE;
sub decode_codes_to_cfg_cached {
    my ($arr) = @_;
    return $_DECODE_CACHE{join ',', @$arr} if $_DECODE_CACHE{join ',', @$arr};

    my %h = map { $CODE_MAP{$_} => 0 } keys %CODE_MAP;
    for (@$arr) { /^!/ && next; $h{ $CODE_MAP{$_} } = 1 }
    $_DECODE_CACHE{join ',', @$arr} = \%h;
}

sub choose_cfg { normalize_integrity_cfg($FILES{ $_[0] }) }
sub file_hash  { fast_file_hash::fast_file_hash(@_) }

# ─── Attr helpers ---------------------------------------------------------
sub _attr          { $_[0] . '.' . $_[1] }
sub store_team_attr { set_file_attr(@_)     }
sub load_team_attr  { get_file_attr(@_)     }

# ══════════════════════════════════════════════════════════════════════════
# ─── Tag material helper --------------------------------------------------
sub _material_hlist {
    my ($exe, $exe_spec_dec, $meta) = @_;

    my @parts = ( file_hash($exe, $exe_spec_dec) );

    if (my $pp = $meta->{ppid}) {
        my $p_spec_dec = decode_codes_to_cfg($pp->{spec});
        push @parts, file_hash($pp->{path}, $p_spec_dec);
    }

    push @parts, @{ $meta->{patterns} // [] };

    join '', map { PATH_SEP . $_ } @parts;
}

# ══════════════════════════════════════════════════════════════════════════
# ─── Canonicalise a config-file pattern (NO tilde expansion now) ──────────
sub _canon_cfg_pattern {
    my ($pat) = @_;
    return ($pat =~ /[\*\?\[]/)        # keep globs (incl. '~') verbatim
         ? $pat
         : (abs_path($pat) || $pat);   # absolute path for literals only
}


sub register_team {
    my ($team, $def, $master) = @_;

    my $exe = $def->{pid} or return;
    -r $exe or do { D "[register:$team] pid unreadable $exe"; return };

    # executable spec
    my $exe_spec_dec = choose_cfg($exe);
    my $exe_spec_enc = encode_cfg_to_codes($exe_spec_dec);

    # parent spec (optional, only if in %FILES)
    my $pp_meta;
    if (my $pp = $def->{ppid}) {
        if (exists $FILES{$pp} && -r $pp) {
            my $pp_spec_dec = choose_cfg($pp);
            $pp_meta = {
                #path => abs_path($pp), ## file_hash handles everything, we just store the path (so NO abs_path needeed)
                path => $pp,
                spec => encode_cfg_to_codes($pp_spec_dec),
            };
        }
    }

    # config patterns (glob strings as-is)
    my @patterns = map { _canon_cfg_pattern($_) } @{ $def->{configs} // [] };
    @patterns = sort @patterns;

    # compute HMAC tag
    my $Ki  = hmac('BLAKE2b_256', $master, "TEAM-$team");
    my $tag = hmac('BLAKE2b_256', $Ki,
                   TAG_PREFIX . _material_hlist($exe, $exe_spec_dec,
                                                { ppid => $pp_meta, patterns => \@patterns }));

    # assemble meta structure
    my $meta = {
        v        => 1,                     # version for forward-compat
        spec     => $exe_spec_enc,
        patterns => \@patterns,
        tag      => $tag,
    };
    $meta->{ppid}      = $pp_meta           if $pp_meta;
    $meta->{uid}       = $def->{uid}        if $def->{uid};
    $meta->{walk_back} = $def->{walk_back}  if exists $def->{walk_back};

    store_team_attr($exe, _attr(XATTR_TEAM, $team), $meta)
        or D "[register:$team] failed store_team_attr";

    D "[register:$team] OK";
}

# ══════════════════════════════════════════════════════════════════════════
# ─── Verification (exe only) ──────────────────────────────────────────────
sub verify_team {
    my ($team, $master) = @_;
    my $exe = $TEAMS{$team}{pid} or return;

    my $meta = load_team_attr($exe, _attr(XATTR_TEAM, $team))
        or do { D "[verify:$team] missing team attr"; return };

    my $exe_spec_dec = decode_codes_to_cfg($meta->{spec});
    my $Ki           = hmac('BLAKE2b_256', $master, "TEAM-$team");
    my $cmp          = hmac('BLAKE2b_256', $Ki,
                            TAG_PREFIX . _material_hlist($exe, $exe_spec_dec, $meta));

    unless (secure_bcmp($cmp, $meta->{tag})) {
        D "[verify:$team] tag mismatch";
        return;
    }
    D "[verify:$team] OK";
    1;
}

# ══════════════════════════════════════════════════════════════════════════
# ─── Exec⇆Config verifier -------------------------------------------------
sub list_teams {
    my ($exe) = @_;
    grep { get_file_attr($exe, _attr(XATTR_TEAM, $_)) } keys %TEAMS;
}


# ─── Pattern vs. config-file matcher (tilde expanded per user) ────────────
sub _cfg_match {
    my ($patterns, $file) = @_;

    # uid of the concrete file we’re testing – useful for bare “~/”
    my $file_uid  = (stat $file)[4] // undef;
    my $file_home = defined $file_uid ? (getpwuid($file_uid))[7] : undef;

    for my $pat (@$patterns) {
        my $p = $pat;

        # Expand leading "~" or "~user" if present
        if ($p =~ m{^~([^/]*)/?(.*)}) {
            my ($user, $rest) = ($1, $2 // '');
            my $home;

            if ($user eq '') {                               # bare "~"
                $home = $file_home;                          # owner of $file
            } else {                                         # "~user"
                $home = (getpwnam($user))[7];                # named user
            }
            next unless defined $home && length $home;       # no such user

            $p = $home . '/' . $rest;
        }

        return 1 if fnmatch($p, $file, FNM_PATHNAME | FNM_PERIOD);
    }
    return 0;
}

sub verify_exe_config {
    my ($exe, $cfg) = @_;
    return unless -r $exe && -r $cfg;
    my $abs_cfg = abs_path($cfg) or return;

    my $master = read_write::read(MASTER_PATH);
    return unless defined $master && length($master) == MASTER_SIZE;

    for my $team (list_teams($exe)) {
        my $meta = load_team_attr($exe, _attr(XATTR_TEAM, $team)) or next;
        next unless _cfg_match($meta->{patterns}, $abs_cfg);

        my $exe_spec_dec = decode_codes_to_cfg($meta->{spec});
        my $Ki           = hmac('BLAKE2b_256', $master, "TEAM-$team");
        my $cmp          = hmac('BLAKE2b_256', $Ki,
                                TAG_PREFIX . _material_hlist($exe, $exe_spec_dec, $meta));

        return 1 if secure_bcmp($cmp, $meta->{tag});
    }
    undef;
}

# ══════════════════════════════════════════════════════════════════════════
# ─── Matrix printer (fixed widths) ----------------------------------------
sub verify_linkage {
    my @rows;

    for my $team (sort keys %TEAMS) {
        my $exe  = $TEAMS{$team}{pid};
        my $meta = load_team_attr($exe, _attr(XATTR_TEAM, $team))
            or next;

        # if we had a parent‐PID, mark it with '*' to show we checked it
        my $pp_raw  = $meta->{ppid}{path} // '';
        my $pp_path = $pp_raw ? "$pp_raw [i]" : '';

        # UID list, WalkBack flag, and integrity spec codes
        my $uid_list = @{ $meta->{uid} // [] }
                     ? join(',', @{ $meta->{uid} })
                     : '';
        my $walk     = $TEAMS{$team}{walk_back} ? 'yes' : 'no';
        my $spec_str = join(',', @{ $meta->{spec} });

        # expand each config pattern
        for my $pat (@{ $meta->{patterns} }) {
            my @matches = ($pat =~ /[\*\?\[]/)
                          ? map { abs_path($_) } glob($pat)
                          : ($pat);
            @matches = ('<none matched>') unless @matches;

            for my $cfg (@matches) {
                my $exists   = -e $cfg ? 'yes' : 'no';
                my $readable = -r $cfg ? 'yes' : 'no';
                my $result   = ($exists eq 'yes' && $readable eq 'yes'
                               && verify_exe_config($exe,$cfg))
                              ? '✓' : '✗';

                push @rows, [
                    $team,
                    $exe,
                    $pp_path,
                    $uid_list,
                    $walk,
                    $spec_str,
                    $cfg,
                    $exists,
                    $readable,
                    $result,
                ];
            }
        }
    }

    # headers including our PPID column
    my @hdrs   = qw(Team PID PPID UIDs WalkBack Spec Config Exists Readable Result);
    my @widths = map { length $_ } @hdrs;

    # compute column widths
    # compute column widths
    for my $r (@rows) {
        # for each column index in this row...
        for my $i (0 .. $#$r) {
            my $len = length $r->[$i];
            # if this cell is wider than our current max, update it
            $widths[$i] = $len if $len > $widths[$i];
        }
    }

    # print header
    say "\n=== Linkage Verification Matrix ===";
    printf "%-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %s\n",
        $widths[0], $hdrs[0],
        $widths[1], $hdrs[1],
        $widths[2], $hdrs[2],
        $widths[3], $hdrs[3],
        $widths[4], $hdrs[4],
        $widths[5], $hdrs[5],
        $widths[6], $hdrs[6],
        $widths[7], $hdrs[7],
        $widths[8], $hdrs[8],
        $hdrs[9];
    say '-' x (sum(@widths) + 3*(scalar @hdrs - 1) + length $hdrs[-1]);

    # print rows
    for my $r (@rows) {
        printf "%-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %s\n",
            $widths[0], $r->[0],
            $widths[1], $r->[1],
            $widths[2], $r->[2],
            $widths[3], $r->[3],
            $widths[4], $r->[4],
            $widths[5], $r->[5],
            $widths[6], $r->[6],
            $widths[7], $r->[7],
            $widths[8], $r->[8],
            $r->[9];
    }

    say '-' x (sum(@widths) + 3*(scalar @hdrs - 1) + length $hdrs[-1]);
}

sub sum { my $s = 0; $s += $_ for @_; return $s }

# ══════════════════════════════════════════════════════════════════════════
# ─── Master key -----------------------------------------------------------
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

# ─── secure_bcmp ----------------------------------------------------------
sub secure_bcmp {
    my ($a,$b)=@_;
    return unless defined $a && defined $b && length($a)==length($b);
    my $d=0; $d |= (ord substr($a,$_,1)) ^ (ord substr($b,$_,1)) for 0..length($a)-1;
    !$d;
}

# END

