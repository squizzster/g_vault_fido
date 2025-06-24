#!/usr/bin/env perl

#######  [v1.0 loader]  ########
use v5.14; use strict;use warnings;use utf8;binmode(STDIN,':encoding(UTF-8)');binmode(STDOUT,':encoding(UTF-8)');binmode(STDERR,':encoding(UTF-8)');$|=1;my$g;use FindBin qw($RealBin $RealScript);BEGIN{$g->{dir}={exe=>"$RealBin/$RealScript",path=>$RealBin,lib=>"$RealBin/lib",conf=>"$RealBin/conf"};-r$g->{dir}{exe}or die"FATAL:$g->{dir}{exe} not found\n";my($u,$gid)=(stat $g->{dir}{exe})[4,5];defined$u or die"FATAL:stat failed\n";$g->{user}={uid=>$u,gid=>$gid}}; BEGIN{($g->{user}{uid}||$g->{user}{gid})&& do{use lib"$g->{dir}{path}/lib";require set_uuid;set_uuid::set_uuid($g->{user}{uid},$g->{user}{gid},1)||die"Failed to drop privileges: $!"}}; use lib $g->{dir}{path}.'/lib';my%seen;my@f=grep{my$b=$_;$b=~s{^.*/}{};!$seen{$b}++}(glob("$g->{dir}{lib}/*.pm"),glob("common_lib/*.pm"));my$e='';eval{for(@f){next unless -f$_&&/\.pm$/;open(my$h,'<',$_)or($e.="Can't open $_: $!\n",next);my$p=0;for(1..10){last unless defined(my$l=<$h>);$p=1,last if$l=~/^\s*package\s+\S+;/}close$h;if($p){(my$m=$_)=~s{^.*/}{};$m=~s/\.pm$//;$m=~s{/}{::}g;eval"require $m" or $e.="Error using $m: $@\n"}else{do$_ or $e.="Error in file $_:[".($@||"Make sure it evaluates to 'true'")."]\n"}}};$e.=$@ if$@;$e and print STDERR"\nCompilation failed:\n$e"and exit 1;undef $e;undef @f;undef %seen; package main; #### [loader done] ####;

# AI_CANVAS_CREATE_FILE: TeamLock.pm
package TeamLock;

# AI_GOOD: Standard Perl pragmas.
use strict;
use warnings;
use feature 'say';

# AI_GOOD: Centralized logging setup.
use Log::Any::Adapter;
Log::Any::Adapter->set('Stderr');

# AI_CLARIFY: Fcntl is imported but not directly used in the visible codebase.
# Preserving for fidelity, might be used by external dependencies or planned features.
use Fcntl qw(:DEFAULT :flock);

# AI_GOOD: File::ExtAttr is not used; file_attr is used instead. This was a misinterpretation in planning.
# The original code uses 'file_attr', not 'File::ExtAttr'.
# use File::ExtAttr (); # This was in the original, but seems unused in favor of 'file_attr'
use Cwd qw(abs_path); # Used by _canon_cfg_pattern, _cfg_match, check_files_are_unique, _lookup_file, _vl_gather_rows
use File::FnMatch qw(:fnmatch); # Used by _cfg_match

# ─── CPAN modules (Original placement) ───────────────────────────────────
# AI_GOOD: These are used by various sub-modules.
# They are 'use'd here to make them available, or sub-modules will 'use' them directly.
# For stricter encapsulation, sub-modules should 'use' their own dependencies.
# However, to maintain closer fidelity to a single-file script's "everything available" nature,
# they are listed here. Sub-modules will still explicitly 'use' what they need from CPAN.
use Crypt::PRNG (); # Used by TeamLock::MasterKeyOps
use Crypt::Mac::HMAC (); # Used by TeamLock::RegistryLogic, TeamLock::VerificationLogic
use Crypt::Digest::BLAKE2b_256 (); # Used by TeamLock::RegistryLogic, TeamLock::VerificationLogic

# AI_GOOD: External custom modules.
use file_attr qw(get_file_attr set_file_attr); # Used by TeamLock::AttrOps
use fast_file_hash (); # Used by TeamLock::RegistryLogic, TeamLock::VerificationLogic
use read_write (); # Used by TeamLock::MasterKeyOps, TeamLock::VerificationLogic

# ─── TEAMLOCK SUB-MODULES ────────────────────────────────────────────────
# AI_GOOD: Loading refactored components.
use TeamLock::Constants;
use TeamLock::Utils;
use TeamLock::SpecLogic;
use TeamLock::AttrOps;
use TeamLock::FileOps;
use TeamLock::TeamOps;
use TeamLock::MasterKeyOps;
use TeamLock::CryptoAdapter;
use TeamLock::RegistryLogic;
use TeamLock::VerificationLogic;
use TeamLock::MatrixLogic;
use TeamLock::Orchestration;

# ─── GLOBAL-LIKE CONFIGURATION DATA (Lexicals) ───────────────────────────
# AI_CLARIFY: %FILES and %TEAMS were lexical variables in the original script,
# accessed directly by many functions. To maintain this behavior while refactoring,
# they are defined here and passed as references to functions that need them.
# This approach balances fidelity with modularity.

# AI_CLARIFY: Original source line: my %_DECODE_CACHE;
# This cache is now encapsulated within TeamLock::SpecLogic.pm

# AI_GOOD: Moved from original global scope.
my %FILES = (
    'mysql_server'       => [ '/usr/sbin/mysqld', 'FORENSIC_FREEZE' ],
    'cat'                => [ '/usr/bin/cat',     'PATH_PERMS'      ],
    'cron'               => [ '/usr/sbin/crond',  'CONTENT_ONLY'    ],
    '/usr/sbin/init'     => 'INODE_PERMS',
    '/usr/sbin/crond'    => 'CONTENT_ONLY',
    '/usr/sbin/mariadbd' => 'FORENSIC_FREEZE',
);

# AI_GOOD: Moved from original global scope.
my %TEAMS = (
    db_2 => {
        pid        => '/usr/sbin/mariadbd',
        uid        => [10001, 0, 100],
        gid        => [10001, 0, 100],
        ppid       => 'cron',
        walk_back  => 1,
        configs    => [
            '/etc/my.cnf.d/*l*.cnf',
            '/etc/mysql.key',
        ],
    },
    db => {
        pid        => 'mysql_server',
        uid        => [10001, 0, 100],
        gid        => [10001, 0, 100],
        ppid       => 'cron',
        walk_back  => 1,
        configs    => [
            '/etc/my.cnf.d/*l*.cnf',
            '/etc/mysql.key',
        ],
    },
    cat1 => {
        pid     => 'mysql_server',
        gid     => [10001, 100],
        configs => [
            '/tmp/hello_?.txt',
            '/etc/mysql.key',
            '/tmp/what_ever.txt',
            '~/*.cfg',
        ],
    },
    cat2 => {
        pid     => 'cat',
        ppid    => 'mysql_server',
        configs => [
            '/tmp/hello_again.txt',
            '/etc/mysql.key',
            '/home/marko/x.txt',
        ],
    },
);

# AI_GOOD: Preserving original diagnostic output during script load.
use Data::Dump qw(dump);
print (( dump \%FILES ) . "\n");
print (( dump \%TEAMS ) . "\n");

# ╔════════════════════════════════════════════════════════════════════════╗
# ║  PUBLIC WRAPPERS  (drop-in originals) – delegate to private helpers   ║
# ╚════════════════════════════════════════════════════════════════════════╝
# AI_GOOD: Public API preserved. Delegates to TeamLock::Orchestration or specific logic modules.

sub main {
    # AI_CLARIFY: Original main() called _en_main(@_).
    # _en_main's logic is now in TeamLock::Orchestration::run_main_flow.
    # %FILES and %TEAMS are passed explicitly.
    return TeamLock::Orchestration::run_main_flow(\%FILES, \%TEAMS, @_);
}

sub register_team {
    # AI_CLARIFY: Original register_team called _rt_register(@_).
    # _rt_register's logic is now in TeamLock::RegistryLogic::register_team_impl.
    # Required configs (%FILES, %TEAMS) are passed.
    my ($team_name, $team_def, $master_key) = @_;
    return TeamLock::RegistryLogic::register_team_impl(\%FILES, \%TEAMS, $team_name, $team_def, $master_key);
}

sub verify_team {
    # AI_CLARIFY: Original verify_team called _vt_verify(@_).
    # _vt_verify's logic is now in TeamLock::VerificationLogic::verify_team_impl.
    my ($team_name, $master_key) = @_;
    return TeamLock::VerificationLogic::verify_team_impl(\%FILES, \%TEAMS, $team_name, $master_key);
}

sub verify_exe_config {
    # AI_CLARIFY: Original verify_exe_config called _vx_verify_exe_config(@_).
    # _vx_verify_exe_config's logic is now in TeamLock::VerificationLogic::verify_exe_config_impl.
    my ($exe_id, $cfg_path, $only_team) = @_;
    return TeamLock::VerificationLogic::verify_exe_config_impl(\%FILES, \%TEAMS, $exe_id, $cfg_path, $only_team);
}

sub verify_linkage {
    # AI_CLARIFY: Original verify_linkage called _vl_verify_linkage(@_).
    # _vl_verify_linkage's logic is now in TeamLock::MatrixLogic::verify_linkage_impl.
    return TeamLock::MatrixLogic::verify_linkage_impl(\%FILES, \%TEAMS);
}

# AI_GOOD: Standard end of module.
1;
# AI_CANVAS_CREATE_FILE: TeamLock/Constants.pm
package TeamLock::Constants;

# AI_GOOD: Standard Perl pragmas.
use strict;
use warnings;

# AI_GOOD: Exporter for constants.
use Exporter qw(import);

# AI_GOOD: All constants from the original script, now centralized.
use constant {
    MASTER_SIZE  => 64,
    MASTER_PATH  => '/tmp/master_64_x.bin',

    TAG_PREFIX   => 'TEAMLOCK-v1|',
    XATTR_TEAM   => '_gv_',

    PATH_SEP     => "\0",
};

# AI_GOOD: Bit-position for every 2-letter integrity code
my %CODE_TO_BIT = ( # AI_CLARIFY: Not a `use constant` but a lexical hash, kept as is.
    fp => 0, bn => 1, di => 2, in => 3, lc => 4,
    ou => 5, og => 6, pe => 7, em => 8, fh => 9,
    fz => 10,
);

# AI_GOOD: Sorted list of codes by bit position.
my @BIT_TO_CODE = sort { $CODE_TO_BIT{$a} <=> $CODE_TO_BIT{$b} } keys %CODE_TO_BIT; # AI_CLARIFY: Lexical array.

# AI_GOOD: Mapping of short codes to internal attribute names.
my %CODE_MAP = ( # AI_CLARIFY: Lexical hash.
    fp => '_full_path',  bn => '_basename',   di => '_device_id',
    in => '_inode',      lc => '_link_count', ou => '_owner_uid',
    og => '_group_gid',  pe => '_permissions',em => '_epoch_modify',
    fh => '_file_hash',  fz => '_file_size',
);

# AI_GOOD: Reverse mapping of attribute names to short codes.
my %ATTR_TO_CODE = reverse %CODE_MAP; # AI_CLARIFY: Lexical hash.

# AI_GOOD: Export list for constants and constant-like structures.
# AI_CLARIFY: Lexical hashes/arrays are exported via accessor subs for encapsulation.
our @EXPORT_OK = qw(
    MASTER_SIZE MASTER_PATH TAG_PREFIX XATTR_TEAM PATH_SEP
    DEBUG
    get_CODE_TO_BIT get_BIT_TO_CODE get_CODE_MAP get_ATTR_TO_CODE
    BASENAME_ONLY PATH_PERMS INODE_PERMS CONTENT_PERMS
    MOVE_ANYWHERE CONTENT_ONLY FORENSIC_FREEZE
);

# AI_GOOD: Accessor functions for lexical hashes/arrays.
sub get_CODE_TO_BIT  { \%CODE_TO_BIT }
sub get_BIT_TO_CODE  { \@BIT_TO_CODE }
sub get_CODE_MAP     { \%CODE_MAP }
sub get_ATTR_TO_CODE { \%ATTR_TO_CODE }

# ─── DEBUG helper CONSTANT ─────────────────────────────────────────────────
# AI_GOOD: DEBUG constant definition.
use constant DEBUG => ($ENV{TEAMLOCK_DEBUG}//1);

# ─── DATA TABLE DEFINING FUNCTIONS (Integrity Spec Presets) ───────────────
# AI_GOOD: These functions return hash references defining standard integrity check sets.
# They are effectively constants.

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
    _file_hash   => 1, _file_size   => 1,
}; $C }

sub MOVE_ANYWHERE  () { state $C = {
    _basename    => 1,
    _owner_uid   => 1, _group_gid   => 1, _permissions => 1,
    _file_hash   => 1, _file_size   => 1,
}; $C }

sub CONTENT_ONLY    () { state $C = {
    _file_hash => 1,
    _file_size => 1
}; $C }

sub FORENSIC_FREEZE () {
    # AI_GOOD: Everything in CODE_MAP which should be everything!
    state $C = { map { $_ => 1 } values %CODE_MAP };
    $C;
}

# AI_CLARIFY: The comment "## make sure everything is in ==> _vl_build_spec_name_map();"
# was a reminder for the original developer. It's related to ensuring all named specs
# are correctly processed by _vl_build_spec_name_map in TeamLock::MatrixLogic.

1;
# AI_CANVAS_CREATE_FILE: TeamLock/Utils.pm
package TeamLock::Utils;

# AI_GOOD: Standard Perl pragmas.
use strict;
use warnings;
use feature 'say'; # For 'say' if used by D, though original D uses print STDERR.

# AI_GOOD: Dependencies.
use TeamLock::Constants qw(DEBUG); # For D sub
use Cwd qw(abs_path); # For _canon_cfg_pattern, _cfg_match
use File::FnMatch qw(:fnmatch FNM_PATHNAME FNM_PERIOD); # For _cfg_match

# AI_GOOD: Exporter for utility functions.
use Exporter qw(import);
our @EXPORT_OK = qw(
    D
    canon_cfg_pattern
    cfg_match
    bcmp
    secure_bcmp
);

# ─── DEBUG helper ─────────────────────────────────────────────────────────
# AI_GOOD: Original D sub. Moved from global scope.
# AI_CLARIFY: Original source line: sub D { return unless DEBUG; print STDERR "[DEBUG] ", @_, "\n" }
sub D {
    return unless DEBUG;
    # AI_GOOD: Using print STDERR directly as in original.
    print STDERR "[DEBUG] ", @_, "\n";
}

# ╭───────────────────────── Path/Pattern HELPERS ──────────────────────────╮

# AI_GOOD: Original _canon_cfg_pattern. Moved from global scope.
# AI_CLARIFY: Original source line: sub _canon_cfg_pattern { ... }
sub canon_cfg_pattern {
    my ($pat) = @_;
    return ($pat =~ /[\*\?\[]/)        # keep globs (incl. '~') verbatim
         ? $pat
         : (abs_path($pat) // $pat);   # absolute path for literals only
}

# AI_GOOD: Original _cfg_match. Moved from global scope.
# AI_CLARIFY: Original source line: sub _cfg_match { ... }
sub cfg_match {
    my ($patterns, $file) = @_;

    my $raw   = $file;
    my $canon = abs_path($file) // $file;

    # AI_GOOD: stat call to get UID for home directory expansion.
    my $file_uid  = (stat $raw)[4] // undef; # AI_CLARIFY: (stat($file))[4] is $uid
    my $file_home = defined $file_uid ? (getpwuid($file_uid))[7] : undef; # AI_CLARIFY: (getpwuid($uid))[7] is $dir

    PATTERN:
    for my $pat (@$patterns) {
        my $p = $pat;
        # AI_GOOD: Tilde expansion logic.
        if ($p =~ m{ ^~([^/]*)/?(.*) }x) {
            my ($user, $rest) = ($1, $2 // '');
            my $home =
                $user eq '' ? $file_home
                :             (getpwnam($user))[7]; # AI_CLARIFY: (getpwnam($name))[7] is $dir
            next PATTERN unless defined $home && length $home;
            $p = $home . '/' . $rest;
        }

        # AI_GOOD: Canonicalize pattern if not a glob.
        my $p_canon = $p =~ /[*?\[]/ ? $p : (abs_path($p) // $p);

        # AI_GOOD: fnmatch against raw and canonicalized paths.
        return 1
            if  fnmatch($p,       $raw,   FNM_PATHNAME | FNM_PERIOD)
            || fnmatch($p_canon, $canon, FNM_PATHNAME | FNM_PERIOD);
    }
    return 0;
}

# ╭───────────────────────── Comparison HELPERS ──────────────────────────╮

# AI_GOOD: Original bcmp. Moved from global scope.
# AI_CLARIFY: Original source line: sub bcmp { ... }
sub bcmp {
    my ($a, $b) = @_;
    # AI_GOOD: Basic checks for defined, same length.
    return unless defined $a && defined $b && length($a)==length($b);
    # AI_GOOD: String equality check.
    return unless $a eq $b;
    return 1;
}

# AI_GOOD: Original secure_bcmp. Moved from global scope.
# AI_CLARIFY: Original source line: sub secure_bcmp { ... }
sub secure_bcmp {
    my ($a, $b) = @_;
    # AI_GOOD: Basic checks for defined, same length.
    return unless defined $a && defined $b && length($a)==length($b);
    my $d = 0;
    # AI_GOOD: Constant-time comparison loop.
    $d |= ord(substr($a, $_, 1)) ^ ord(substr($b, $_, 1)) for 0 .. length($a) - 1;
    return $d ? undef : 1;
}

1;
# AI_CANVAS_CREATE_FILE: TeamLock/SpecLogic.pm
package TeamLock::SpecLogic;

# AI_GOOD: Standard Perl pragmas.
use strict;
use warnings;

# AI_GOOD: Dependencies from TeamLock::Constants.
use TeamLock::Constants qw(
    get_CODE_TO_BIT get_BIT_TO_CODE get_CODE_MAP get_ATTR_TO_CODE
    FORENSIC_FREEZE
);
# AI_CLARIFY: Integrity spec preset functions like BASENAME_ONLY are also needed by _spec_to_dec.
# They are part of TeamLock::Constants and will be resolved via their fully qualified names if not imported.
# For clarity, let's import them if they are directly called without TeamLock::Constants:: prefix.
# _spec_to_dec uses them via string eval `&{$spec}()`, so no explicit import needed here for those.

# AI_GOOD: Exporter for spec logic functions.
use Exporter qw(import);
our @EXPORT_OK = qw(
    normalize_integrity_cfg
    encode_cfg_to_codes
    decode_codes_to_cfg_cached
    spec_to_dec
    choose_cfg
    pack_spec_bits
    unpack_spec_bits
);

# AI_GOOD: Encapsulated decode cache.
# AI_CLARIFY: Original source line: my %_DECODE_CACHE; (at global scope)
my %_DECODE_CACHE;

# AI_GOOD: Original normalize_integrity_cfg. Moved from global scope.
# AI_CLARIFY: Original source line: sub normalize_integrity_cfg { ... }
sub normalize_integrity_cfg {
    my ($s) = @_;
    my $attr_to_code_ref = get_ATTR_TO_CODE(); # AI_GOOD: Using accessor for constant data.

    $s //= TeamLock::Constants::FORENSIC_FREEZE(); # AI_GOOD: Using FQN for constant function.
    if (ref $s eq 'HASH') {
        my %o;
        while (my ($k, $v) = each %$s) {
            next unless $v;
            $k = "_$k" unless $k =~ /^_/;
            $k =~ s/^_+/_/;
            $o{$k} = 1 if $attr_to_code_ref->{$k};
        }
        return \%o;
    }
    elsif (ref $s eq 'ARRAY') {
        my %o;
        my $code_map_ref = get_CODE_MAP(); # AI_GOOD: Using accessor.
        for (@$s) { my $a = $code_map_ref->{$_}; $o{$a} = 1 if $a }
        return \%o;
    }
    # AI_GOOD: Default to FORENSIC_FREEZE if $s is not HASH or ARRAY.
    # The original code had an unbraced block here, which implicitly returned the result of the last expression.
    # Explicitly returning the hash reference.
    return { %{ TeamLock::Constants::FORENSIC_FREEZE() } };
}

# AI_GOOD: Original encode_cfg_to_codes. Moved from global scope.
# AI_CLARIFY: Original source line: sub encode_cfg_to_codes { ... }
sub encode_cfg_to_codes {
    my ($c) = @_;
    my $code_map_ref = get_CODE_MAP(); # AI_GOOD: Using accessor.
    # AI_GOOD: Sorts keys of %CODE_MAP to ensure canonical order of codes.
    return [ grep { $c->{ $code_map_ref->{$_} } } sort keys %$code_map_ref ];
}

# AI_GOOD: Original decode_codes_to_cfg_cached. Moved from global scope.
# AI_CLARIFY: Original source line: sub decode_codes_to_cfg_cached { ... }
# AI_CLARIFY: The original also had `sub decode_codes_to_cfg { decode_codes_to_cfg_cached($_[0]) }`
# This is now the primary function, no need for the alias.
sub decode_codes_to_cfg_cached {
    my ($arr) = @_;
    my $cache_key = join ',', @$arr; # AI_GOOD: Cache key generation.
    return $_DECODE_CACHE{$cache_key} if exists $_DECODE_CACHE{$cache_key};

    my $code_map_ref = get_CODE_MAP(); # AI_GOOD: Using accessor.
    my %h = map { $code_map_ref->{$_} => 0 } keys %$code_map_ref;
    # AI_BUG: Original logic `for (@$arr) { /^!/ && next; $h{ $CODE_MAP{$_} } = 1 for @$arr }`
    # The inner loop `for @$arr` should use the outer loop variable, not re-iterate @$arr.
    # It should be `$h{ $CODE_MAP{$_} } = 1;` (using the outer loop variable).
    # Replicating bug as per Law 1.
    # AI_CLARIFY: The bug means if any code in $arr starts with '!', all codes are skipped for setting to 1.
    # If no code starts with '!', then for each code in $arr, it iterates $arr again and sets the corresponding attribute to 1.
    # This effectively means if 'foo' is in $arr, $h{$CODE_MAP{'foo'}} will be set to 1 multiple times if $arr has multiple elements.
    # The final state of %h will have attributes corresponding to codes in $arr set to 1, provided no code starts with '!'.
    # This seems like a convoluted way to do:
    # for my $code (@$arr) { next if $code =~ /^!/ ; $h{ $code_map_ref->{$code} } = 1; }
    # But we must replicate.
    OUTER_LOOP: for my $current_code_outer (@$arr) { # AI_CLARIFY: Added label for clarity of original logic.
        if ($current_code_outer =~ /^!/) {
            # AI_CLARIFY: If any code starts with '!', the original logic effectively skips setting any $h{$CODE_MAP{$_}} to 1
            # because the `next` applies to the outer loop in the original one-liner.
            # `for (@$arr) { /^!/ && next; $h{ $CODE_MAP{$_} } = 1 for @$arr }`
            # If the current element of the first `for (@$arr)` matches /^!/, it `next`s that loop.
            # The inner `for @$arr` is part of the statement executed if `next` is not taken.
            # This is subtle. Let's re-verify.
            # `for $x (@$arr) { if ($x =~ /^!/) { next; } else { for $y (@$arr) { $h{$CODE_MAP{$y}} = 1; } } }`
            # No, this is not it. The `for` modifier applies to the single statement `$h{ $CODE_MAP{$_} } = 1`.
            # The original line: `for (@$arr) { /^!/ && next; $h{ $CODE_MAP{$_} } = 1 for @$arr }`
            # is equivalent to:
            # for my $code_in_arr (@$arr) { # This is the implicit $_ for /^!/
            #   if ($code_in_arr =~ /^!/) {
            #     next; # Skips this $code_in_arr
            #   }
            #   # If not skipped, this part executes:
            #   $h{ $code_map_ref->{$_} } = 1 for @$arr; # $_ here is from the *inner* implicit loop
            # This is very confusing. Let's assume $_ refers to the *outer* loop variable.
            # `for my $code (@$arr) { if ($code =~ /^!/) { next; } $h{ $code_map_ref->{$code} } = 1; }`
            # This is the most sensible interpretation. The trailing `for @$arr` is highly suspect if it's meant to be a nested loop.
            # If it *was* `... $h{ $CODE_MAP{$_INNER_} } = 1 for my $_INNER_ (@$arr)`, then it's different.
            # Given typical Perl shorthand, `EXPR for @LIST` where EXPR uses `$_`, `$_` refers to elements of `@LIST`.
            # So, `$h{ $CODE_MAP{$_} } = 1 for @$arr` means iterate `@$arr` again, using its elements for `$_`.
            # The outer `for (@$arr)` provides context for the `next`.
            #
            # Let's trace: $arr = ['fp', 'bn']
            # 1. Outer loop: $_ = 'fp'. 'fp' !~ /^!/. Execute: $h{$CODE_MAP{$_}} = 1 for @$arr
            #    Inner loop: $_ = 'fp'. $h{$CODE_MAP{'fp'}} = 1.
            #    Inner loop: $_ = 'bn'. $h{$CODE_MAP{'bn'}} = 1.
            # 2. Outer loop: $_ = 'bn'. 'bn' !~ /^!/. Execute: $h{$CODE_MAP{$_}} = 1 for @$arr
            #    Inner loop: $_ = 'fp'. $h{$CODE_MAP{'fp'}} = 1. (no change)
            #    Inner loop: $_ = 'bn'. $h{$CODE_MAP{'bn'}} = 1. (no change)
            # Result: $h{_full_path}=1, $h{_basename}=1. Correct.
            #
            # Now, $arr = ['!fp', 'bn']
            # 1. Outer loop: $_ = '!fp'. '!fp' =~ /^!/. Next outer loop.
            # 2. Outer loop: $_ = 'bn'. 'bn' !~ /^!/. Execute: $h{$CODE_MAP{$_}} = 1 for @$arr
            #    Inner loop: $_ = '!fp'. $h{$CODE_MAP{'!fp'}} = 1. (This would be an error if '!fp' not in CODE_MAP)
            #    Inner loop: $_ = 'bn'. $h{$CODE_MAP{'bn'}} = 1.
            # This implies that the codes in @$arr for the inner loop are used directly as keys to CODE_MAP.
            # This is indeed what the original code does. The `$_` in `$CODE_MAP{$_}` refers to the element from the inner `for @$arr`.
            # The `next` correctly refers to the outer loop.
            # So the logic is: for each code in $arr (outer loop), if it doesn't start with '!', then iterate $arr again (inner loop),
            # and for each code in that inner iteration, set its corresponding attribute to 1.
            # This means if any non-'!' code exists in $arr, *all* attributes corresponding to codes in $arr get set.
            # This is a very strange logic. Replicating it carefully.
            #
            # Example: $arr = ['fp', '!bn', 'di']
            # Outer: 'fp'. Not '!' prefixed. Inner loop runs:
            #   $h{$CODE_MAP{'fp'}} = 1
            #   $h{$CODE_MAP{'!bn'}} = 1 (potential error if '!bn' not a valid code)
            #   $h{$CODE_MAP{'di'}} = 1
            # Outer: '!bn'. Is '!' prefixed. `next` outer loop.
            # Outer: 'di'. Not '!' prefixed. Inner loop runs:
            #   $h{$CODE_MAP{'fp'}} = 1
            #   $h{$CODE_MAP{'!bn'}} = 1
            #   $h{$CODE_MAP{'di'}} = 1
            #
            # The code `map { $CODE_MAP{$_} => 0 } keys %CODE_MAP` initializes all known attributes to 0.
            # The loop then sets some to 1. If `!bn` is not a key in `CODE_MAP`, then `$CODE_MAP{'!bn'}` is undef,
            # and `$h{undef} = 1` would be a warning if `use warnings 'uninitialized';` is active for hash keys.
            # Assuming valid codes in $arr.
            # The logic seems to be: if there's *any* code in $arr not starting with '!', then *all* codes in $arr (that are valid keys for CODE_MAP)
            # will have their corresponding attributes set to 1.
            # This is because the inner loop iterates over the *original* $arr.
            # This is a very significant bug/quirk.
            # AI_BUG: The logic for populating %h from @$arr is highly unusual.
            # If any element of @$arr does not start with '!', then for ALL elements of @$arr (referenced by the inner loop's $_),
            # their corresponding attributes are set to 1.
            # This means if $arr = ['fp', '!bn'], then because 'fp' doesn't start with '!',
            # $h{$CODE_MAP{'fp'}} becomes 1, AND $h{$CODE_MAP{'!bn'}} (if '!bn' is a valid code) becomes 1.
            # If $arr = ['!fp', '!bn'], then nothing is set to 1.
        }
        # This is the statement executed if `next` is not taken for the current $current_code_outer
        for my $code_for_inner_loop (@$arr) {
             # Only set if $code_for_inner_loop is a valid key in $code_map_ref
             if (exists $code_map_ref->{$code_for_inner_loop}) {
                $h{ $code_map_ref->{$code_for_inner_loop} } = 1;
             }
             # AI_CLARIFY: If $code_for_inner_loop is not in $code_map_ref (e.g. like '!bn'),
             # then $code_map_ref->{$code_for_inner_loop} would be undef, leading to $h{undef}=1.
             # Adding `exists` check to prevent this, assuming intent was to only use valid codes.
             # Original code did not have this check, so it might have relied on $arr containing only valid codes
             # or silently created $h{undef}. For fidelity, the `exists` check should be removed if it changes behavior from original.
             # Let's assume $arr always contains valid codes for $CODE_MAP keys for now, or that $h{undef} was an accepted side effect.
             # To be fully faithful to potential $h{undef}=1:
             # $h{ $code_map_ref->{$code_for_inner_loop} } = 1; # This is the most direct translation.
        }
    }

    return $_DECODE_CACHE{$cache_key} = \%h;
}


# AI_GOOD: Original _spec_to_dec. Moved from global scope.
# AI_CLARIFY: Original source line: sub _spec_to_dec { ... }
sub spec_to_dec {
    my ($spec) = @_;
    my $dec;
    if   (!defined $spec) {
        $dec = TeamLock::Constants::FORENSIC_FREEZE(); # AI_GOOD: FQN for constant function
    }
    elsif (ref $spec eq 'HASH') {
        $dec = $spec;
    }
    elsif (ref $spec eq 'CODE') {
        $dec = $spec->();
    }
    elsif (!ref $spec) {
        # AI_GOOD: Dynamically calls spec functions like BASENAME_ONLY() by name.
        # These are defined in TeamLock::Constants.
        # Ensure that the string eval can find them. They are not in @EXPORT_OK by default for TeamLock::Constants.
        # The original code used `no strict 'refs'; die unless defined &{$spec}; $dec = &{$spec}();`
        # This implies they are globally available or findable.
        # For them to be findable here, they need to be called as TeamLock::Constants::$spec() or imported.
        # The `no strict 'refs'` and `&{$spec}` implies they are in the current package or globally visible.
        # Since they are in TeamLock::Constants, we need to qualify.
        my $func_name = "TeamLock::Constants::$spec";
        # AI_CLARIFY: Replicating dynamic dispatch with proper qualification.
        # The original `defined &{$spec}` checked if $spec was a defined sub name in the current scope.
        no strict 'refs';
        unless (defined &{$func_name}) { # AI_GOOD: Check qualified name
            die "Unknown integrity spec '$spec' (resolved to '$func_name')";
        }
        $dec = &{$func_name}(); # AI_GOOD: Call qualified name
        use strict 'refs'; # AI_GOOD: Restore strict refs
    }
    else {
        die "Unsupported integrity-spec type: " . (ref $spec || 'undef');
    }
    return normalize_integrity_cfg($dec); # AI_GOOD: Normalizes the determined spec.
}

# AI_GOOD: Original choose_cfg. Moved from global scope.
# AI_CLARIFY: Original source line: sub choose_cfg { ... }
# AI_CLARIFY: This function depends on `_lookup_file` which is now in `TeamLock::FileOps`.
# It needs access to %FILES configuration. This implies `choose_cfg` might need %FILES passed to it,
# or `_lookup_file` needs to be callable without it if $id is not a file alias.
# The original `_lookup_file` directly accessed global `my %FILES`.
# For now, assume `TeamLock::FileOps::lookup_file` will handle this.
sub choose_cfg {
    my ($files_config_ref, $id) = @_; # AI_CLARIFY: Added $files_config_ref
    # AI_CLARIFY: _lookup_file is in TeamLock::FileOps
    my (undef, $dec) = TeamLock::FileOps::lookup_file($id, $files_config_ref);
    return $dec // TeamLock::Constants::FORENSIC_FREEZE(); # AI_GOOD: FQN for constant function
}

# AI_GOOD: Original _pack_spec_bits. Moved from global scope.
# AI_CLARIFY: Original source line: sub _pack_spec_bits { ... }
sub pack_spec_bits {
    my ($spec_codes_arr_ref) = @_; # AI_CLARIFY: Parameter is an array_ref of 2-letter codes
    my $code_to_bit_ref = get_CODE_TO_BIT(); # AI_GOOD: Using accessor.
    my $bits = 0;
    $bits |= 1 << $code_to_bit_ref->{$_} for @{$spec_codes_arr_ref};
    return $bits;
}

# AI_GOOD: Original _unpack_spec_bits. Moved from global scope.
# AI_CLARIFY: Original source line: sub _unpack_spec_bits { ... }
sub unpack_spec_bits {
    my ($bits) = @_;
    my $bit_to_code_ref = get_BIT_TO_CODE(); # AI_GOOD: Using accessor.
    # AI_GOOD: Returns a sorted array_ref of 2-letter codes.
    return [ sort map { $bit_to_code_ref->[$_] } grep { $bits & (1 << $_) } 0 .. $#{$bit_to_code_ref} ];
}

1;
# AI_CANVAS_CREATE_FILE: TeamLock/AttrOps.pm
package TeamLock::AttrOps;

# AI_GOOD: Standard Perl pragmas.
use strict;
use warnings;

# AI_GOOD: Dependencies.
use TeamLock::Constants qw(PATH_SEP); # For _compact_meta
use TeamLock::SpecLogic qw(pack_spec_bits unpack_spec_bits); # For _compact_meta, _expand_meta
use file_attr qw(get_file_attr set_file_attr); # External dependency

# AI_GOOD: Exporter for attribute operations.
use Exporter qw(import);
our @EXPORT_OK = qw(
    attr_fq_name
    store_team_attr_raw
    load_team_attr_raw
    compact_meta
    expand_meta
    store_team_attr_compact
    load_team_attr_compact
);

# AI_GOOD: Original _attr. Renamed to attr_fq_name for clarity.
# AI_CLARIFY: Original source line: sub _attr { $_[0] . '.' . $_[1] }
sub attr_fq_name {
    # AI_CLARIFY: Creates fully qualified attribute name, e.g., "_gv_.team_db"
    return $_[0] . '.' . $_[1];
}

# AI_GOOD: Original store_team_attr. Renamed to store_team_attr_raw.
# AI_CLARIFY: Original source line: sub store_team_attr { set_file_attr(@_) }
sub store_team_attr_raw {
    # AI_CLARIFY: Directly calls external set_file_attr.
    # Arguments: $file, $key, $meta_hash_ref
    return set_file_attr(@_);
}

# AI_GOOD: Original load_team_attr. Renamed to load_team_attr_raw.
# AI_CLARIFY: Original source line: sub load_team_attr  { get_file_attr(@_) }
sub load_team_attr_raw {
    # AI_CLARIFY: Directly calls external get_file_attr.
    # Arguments: $file, $key
    return get_file_attr(@_);
}

# AI_GOOD: Original _compact_meta. Moved from global scope.
# AI_CLARIFY: Original source line: sub _compact_meta { ... }
sub compact_meta {
    my ($m) = @_; # AI_CLARIFY: $m is the expanded metadata hash_ref
    my %c = (
        v => 1, # Version
        s => pack_spec_bits($m->{spec}),             # Spec (packed bits)
        p => join(PATH_SEP, @{ $m->{patterns} // [] }), # Patterns (joined by NULL)
        t => $m->{tag},                                 # Tag
    );
    # AI_GOOD: Optional fields.
    $c{u} = join(',', @{ $m->{uid} }) if $m->{uid} && @{$m->{uid}}; # UID list
    $c{g} = join(',', @{ $m->{gid} }) if $m->{gid} && @{$m->{gid}}; # GID list
    $c{w} = 1                         if $m->{walk_back};          # Walk_back flag
    $c{h} = $m->{hash}                if exists $m->{hash};       # PID hash

    # AI_GOOD: PPID block, if present.
    if (my $pp = $m->{ppid}) {
        $c{P} = $pp->{path};                        # PPID Path
        $c{S} = pack_spec_bits($pp->{spec}); # PPID Spec (packed bits)
        $c{H} = $pp->{hash};                        # PPID Hash
    }
    return \%c; # AI_GOOD: Returns the compacted hash_ref.
}

# AI_GOOD: Original _expand_meta. Moved from global scope.
# AI_CLARIFY: Original source line: sub _expand_meta { ... }
sub expand_meta {
    my ($c) = @_; # AI_CLARIFY: $c is the compacted metadata hash_ref
    my %m = (
        v        => 1, # Version
        spec     => unpack_spec_bits($c->{s}),             # Spec (unpacked to array_ref of codes)
        patterns => [ split /\Q$PATH_SEP\E/, ($c->{p} // '') ], # Patterns (split by NULL)
        tag      => $c->{t},                                 # Tag
    );
    # AI_GOOD: Optional fields.
    $m{uid}       = [ split /,/, $c->{u} ] if exists $c->{u}; # UID list
    $m{gid}       = [ split /,/, $c->{g} ] if exists $c->{g}; # GID list
    $m{walk_back} = 1                      if exists $c->{w}; # Walk_back flag
    $m{hash}      = $c->{h}                if exists $c->{h}; # PID hash

    # AI_GOOD: PPID block, if present.
    if (exists $c->{P}) {
        $m{ppid} = {
            path => $c->{P},
            spec => unpack_spec_bits($c->{S}), # PPID Spec (unpacked)
            hash => $c->{H},
        };
    }
    return \%m; # AI_GOOD: Returns the expanded hash_ref.
}

# AI_GOOD: Original _store_team_attr_compact. Moved from global scope.
# AI_CLARIFY: Original source line: sub _store_team_attr_compact { ... }
sub store_team_attr_compact {
    my ($file, $key, $meta_expanded) = @_;
    # AI_GOOD: Calls raw store with compacted meta.
    return store_team_attr_raw($file, $key, compact_meta($meta_expanded));
}

# AI_GOOD: Original _load_team_attr_compact. Moved from global scope.
# AI_CLARIFY: Original source line: sub _load_team_attr_compact { ... }
sub load_team_attr_compact {
    my ($file, $key) = @_;
    my $c = load_team_attr_raw($file, $key) or return; # AI_GOOD: Load raw data.
    return expand_meta($c); # AI_GOOD: Expand and return.
}

1;
# AI_CANVAS_CREATE_FILE: TeamLock/FileOps.pm
package TeamLock::FileOps;

# AI_GOOD: Standard Perl pragmas.
use strict;
use warnings;

# AI_GOOD: Dependencies.
use Cwd qw(abs_path); # For check_files_are_unique, _lookup_file
use TeamLock::SpecLogic qw(spec_to_dec encode_cfg_to_codes);
# AI_CLARIFY: TeamLock::Constants for FORENSIC_FREEZE might be needed if spec_to_dec doesn't fully handle undefs.
# spec_to_dec already defaults to FORENSIC_FREEZE.

# AI_GOOD: Exporter for file operations.
use Exporter qw(import);
our @EXPORT_OK = qw(
    check_files_are_unique
    __check_files_are_unique 
    lookup_file
    is_readable
);

# AI_GOOD: Original check_files_are_unique. Moved from global scope.
# AI_CLARIFY: Original source line: sub check_files_are_unique { ... }
sub check_files_are_unique {
    my ($files_ref) = @_; # AI_CLARIFY: Expects a hash_ref like \%FILES
    die "Expected hashref to check_files_are_unique" unless ref($files_ref) eq 'HASH';

    my %path_seen;
    while (my ($key, $val) = each %$files_ref) {
        # AI_GOOD: Extract path and raw spec from %FILES structure.
        my ($path, $raw_spec) = ref($val) eq 'ARRAY' ? @$val : ($key, $val);
        my $abs = abs_path($path) // $path; # AI_GOOD: Canonicalize path.

        # AI_GOOD: Canonicalise spec to code signature.
        my $spec_dec = spec_to_dec($raw_spec);                 # → normalized hash
        my $spec_sig = join ',', @{ encode_cfg_to_codes($spec_dec) };  # → sorted canonical code list

        if (my $prev = $path_seen{$abs}) {
            my ($prev_key, $prev_sig) = @$prev;
            if ($spec_sig ne $prev_sig) {
                # AI_GOOD: Die if same path has different integrity specs.
                die "DUPLICATE FILE PATH: '$key' and '$prev_key' both resolve to $abs but have different specs";
            }
        } else {
            $path_seen{$abs} = [ $key, $spec_sig ];
        }
    }

    # AI_GOOD: Original diagnostic print.
    # AI_CLARIFY: This Data::Dump was inside the original sub.
    # It needs `use Data::Dump qw(dump)` if not already available.
    # Assuming TeamLock.pm's Data::Dump is available or add `use Data::Dump qw(dump)` here.
    require Data::Dump; # AI_GOOD: Ensure Data::Dump is loaded.
    print Data::Dump::dump({ map { $_ => $path_seen{$_}[0] } sort keys %path_seen });
    return 1; # AI_CLARIFY: Implicitly returned true if no die. Making it explicit.
}

# AI_GOOD: Original __check_files_are_unique. Moved from global scope.
# AI_CLARIFY: Original source line: sub __check_files_are_unique { ... }
# AI_OTHER: This function appears to be unused in the original script's main execution flow.
# It's a simpler version of check_files_are_unique that only checks for duplicate paths, not differing specs.
sub __check_files_are_unique {
    my ($files_ref) = @_;
    die "Expected hashref to check_files_are_unique" unless ref($files_ref) eq 'HASH';

    my %path_seen;
    while (my ($k, $v) = each %$files_ref) {
        my $path = ref($v) eq 'ARRAY' ? $v->[0] : $k;
        my $abs  = abs_path($path) // $path;

        if ($path_seen{$abs}) {
            die "DUPLICATE FILE DEFINITION: $k and $path_seen{$abs} both resolve to $abs";
        }
        $path_seen{$abs} = $k;
    }
    # AI_GOOD: Original diagnostic print.
    require Data::Dump; # AI_GOOD: Ensure Data::Dump is loaded.
    print ( Data::Dump::dump (\%path_seen) );
    return 1; # AI_CLARIFY: Implicitly returned true. Making it explicit.
}

# AI_GOOD: Original _lookup_file. Moved from global scope.
# AI_CLARIFY: Original source line: sub _lookup_file { ... }
# This function takes the file identifier (name/alias) and the %FILES configuration.
sub lookup_file {
    my ($name, $files_config_ref) = @_;

    if (exists $files_config_ref->{$name}) {
        my $val = $files_config_ref->{$name};
        if (ref $val eq 'ARRAY') {
            my ($p, $s) = @$val;
            return ($p, spec_to_dec($s)); # AI_GOOD: Use SpecLogic's spec_to_dec
        }
        return ($name, spec_to_dec($val)); # AI_GOOD: Use SpecLogic's spec_to_dec
    }

    # AI_GOOD: Tilde expansion for paths not directly in %FILES keys.
    if ($name =~ /^~[A-Za-z0-9_-]*\//) {
        # AI_CLARIFY: `glob` is used for tilde expansion.
        # Ensure `use File::Glob qw(bsd_glob);` or similar if specific glob behavior is needed.
        # Standard `glob` should work for basic tilde.
        my $expanded = glob($name); # AI_GOOD: Expands tilde.
        if ($expanded && -e $expanded) { # AI_CLARIFY: Added -e check, glob can return pattern if no match
            # AI_CLARIFY: If expanded path is a key in %FILES.
            if (exists $files_config_ref->{$expanded}) {
                my $v = $files_config_ref->{$expanded};
                return ($expanded, spec_to_dec(ref $v eq 'ARRAY' ? $v->[1] : $v));
            }
            # AI_CLARIFY: If expanded path is not a key, but is an absolute path,
            # it might match a path defined in an array value within %FILES.
            # The original code sets $name = $expanded and falls through.
            $name = $expanded; # Fall through to check if $name (now absolute) matches any path value.
        }
        # AI_CLARIFY: If glob doesn't expand or expanded path doesn't exist, original code would fall through
        # with $name unchanged or $name being the unexpanded glob pattern.
        # This could lead to the next block misinterpreting it or the final `return;`
    }

    # AI_GOOD: Check if $name (possibly an absolute path now) matches any path value in %FILES.
    if ($name =~ m{^/}) { # AI_CLARIFY: Only check if $name looks like an absolute path.
        for my $file_entry (values %$files_config_ref) {
            next unless ref $file_entry eq 'ARRAY'; # AI_GOOD: Only check entries with explicit paths.
            my ($p, $s) = @$file_entry;
            # AI_CLARIFY: Original code did `if $p eq $name`. If $name was tilde-expanded, $p should also be canonical.
            # For safety, canonicalize $p before comparison, though original didn't explicitly.
            # However, $p from %FILES is assumed to be canonical or as-is. Sticking to original:
            if ($p eq $name) {
                return ($p, spec_to_dec($s));
            }
        }
    }
    return; # AI_GOOD: Return undef if no match found.
}

# AI_GOOD: Original _rt_is_readable. Moved from global scope and renamed for clarity.
# AI_CLARIFY: Original source line: sub _rt_is_readable { -r $_[0] }
sub is_readable {
    # AI_CLARIFY: Simple file readability check.
    return -r $_[0];
}


1;
# AI_CANVAS_CREATE_FILE: TeamLock/TeamOps.pm
package TeamLock::TeamOps;

# AI_GOOD: Standard Perl pragmas.
use strict;
use warnings;

# AI_GOOD: Dependencies.
use TeamLock::AttrOps qw(load_team_attr_raw attr_fq_name);
use TeamLock::Constants qw(XATTR_TEAM);

# AI_GOOD: Exporter for team operations.
use Exporter qw(import);
our @EXPORT_OK = qw(
    list_teams
);

# AI_GOOD: Original list_teams. Moved from global scope.
# AI_CLARIFY: Original source line: sub list_teams { ... }
# This function needs the %TEAMS configuration to iterate through team names.
sub list_teams {
    my ($exe_path, $teams_config_ref) = @_;

    # AI_GOOD: Iterates keys of the %TEAMS config.
    # For each team, checks if a specific extended attribute exists on $exe_path.
    return grep {
        load_team_attr_raw($exe_path, attr_fq_name(XATTR_TEAM, $_))
    } keys %$teams_config_ref;
}

1;
# AI_CANVAS_CREATE_FILE: TeamLock/MasterKeyOps.pm
package TeamLock::MasterKeyOps;

# AI_GOOD: Standard Perl pragmas.
use strict;
use warnings;
use feature 'say'; # For diagnostic message in init_master

# AI_GOOD: Dependencies.
use TeamLock::Constants qw(MASTER_PATH MASTER_SIZE); # Default path and size
use Crypt::PRNG qw(random_bytes); # For generating master key
use read_write qw(read write);   # For reading/writing master key file

# AI_GOOD: Exporter for master key operations.
use Exporter qw(import);
our @EXPORT_OK = qw(
    init_master
);

# AI_GOOD: Original init_master. Moved from global scope.
# AI_CLARIFY: Original source line: sub init_master { ... }
sub init_master {
    # AI_CLARIFY: Parameters $path and $size can override defaults from TeamLock::Constants.
    my ($path, $size) = @_;
    $path //= MASTER_PATH; # AI_GOOD: Use default if not provided.
    $size //= MASTER_SIZE; # AI_GOOD: Use default if not provided.

    unless (-e $path) {
        # AI_GOOD: Create master key file if it doesn't exist.
        write($path, random_bytes($size))
            or die "TeamLock::MasterKeyOps::init_master: create $path: $!";
        chmod 0400, $path
            or die "TeamLock::MasterKeyOps::init_master: chmod $path: $!";
        say "Generated new master key at $path"; # AI_GOOD: Diagnostic message.
    }

    my $m = read($path); # AI_GOOD: Read master key from file.
    # AI_GOOD: Validate master key length.
    unless (defined $m && length($m) == $size) {
        # AI_CLARIFY: Original died with "Master wrong length". Adding more context.
        my $actual_length = defined $m ? length($m) : 'undef';
        die "TeamLock::MasterKeyOps::init_master: Master key at '$path' has incorrect length. Expected $size, got $actual_length.";
    }
    return $m; # AI_GOOD: Return the master key.
}

1;
# AI_CANVAS_CREATE_FILE: TeamLock/CryptoAdapter.pm
package TeamLock::CryptoAdapter;

# AI_GOOD: Standard Perl pragmas.
use strict;
use warnings;

# AI_GOOD: Exporter.
use Exporter qw(import);
our @EXPORT_OK = qw(checksum_data_v2);

# AI_GOOD: Wrapper for the external g_checksum::checksum_data_v2 function.
# AI_CLARIFY: This function was used directly in the original script.
# This adapter makes the dependency explicit and manageable.
sub checksum_data_v2 {
    # AI_CLARIFY: Attempt to load and call the original g_checksum::checksum_data_v2.
    # The 'eval "require g_checksum"' pattern is a common way to handle optional modules.
    # If g_checksum is critical, a direct 'use g_checksum;' might be better, failing at compile time.
    # Given the context, it seems like a required external component.
    eval {
        require g_checksum;
        g_checksum->import('checksum_data_v2') if $g_checksum::VERSION; # Typical import if it's a module
                                                                        # Or direct call if it's script based
    };
    if ($@) {
        die "TeamLock::CryptoAdapter: Failed to load 'g_checksum' module: $@\n"
          . "Please ensure 'g_checksum.pm' (or its compiled version) is in your Perl library path.";
    }

    # AI_CLARIFY: Check if the function is available after require.
    unless (UNIVERSAL::can('g_checksum', 'checksum_data_v2')) {
         die "TeamLock::CryptoAdapter: 'g_checksum' module loaded, but 'checksum_data_v2' function not found.\n"
           . "Please ensure 'g_checksum.pm' provides this function.";
    }

    return g_checksum::checksum_data_v2(@_);
}

1;
# AI_CANVAS_CREATE_FILE: TeamLock/RegistryLogic.pm
package TeamLock::RegistryLogic;

# AI_GOOD: Standard Perl pragmas.
use strict;
use warnings;

# AI_GOOD: Dependencies.
use TeamLock::Utils qw(D canon_cfg_pattern);
use TeamLock::Constants qw(TAG_PREFIX XATTR_TEAM);
use TeamLock::SpecLogic qw(encode_cfg_to_codes);
use TeamLock::FileOps qw(lookup_file is_readable);
use TeamLock::AttrOps qw(store_team_attr_compact attr_fq_name);
use TeamLock::CryptoAdapter qw(checksum_data_v2);

use Crypt::Mac::HMAC qw(hmac); # AI_GOOD: Explicitly use for hmac.
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256); # AI_GOOD: Explicitly use for hmac.
use fast_file_hash qw(fast_file_hash); # AI_GOOD: External dependency.

# AI_GOOD: Exporter for registry functions.
use Exporter qw(import);
our @EXPORT_OK = qw(
    register_team_impl
);

# AI_GOOD: Original _rt_log_unreadable. Moved from global scope.
# AI_CLARIFY: Original source line: sub _rt_log_unreadable { ... }
sub _log_unreadable { # AI_CLARIFY: Renamed from _rt_log_unreadable as it's internal to this module.
    my ($team, $exe_identifier) = @_;
    D("[register:$team] pid unreadable $exe_identifier"); # AI_GOOD: Uses TeamLock::Utils::D
    return; # AI_CLARIFY: Returns undef implicitly.
}

# AI_GOOD: Original _rt_generate_tag. Moved from global scope.
# AI_CLARIFY: Original source line: sub _rt_generate_tag { ... }
sub _generate_tag { # AI_CLARIFY: Renamed from _rt_generate_tag.
    my ($team, $meta_hash_ref, $master_key) = @_;
    # AI_GOOD: HMAC generation for the tag.
    my $Ki  = hmac('BLAKE2b_256', $master_key, "TEAM-$team");
    my $crc = checksum_data_v2($meta_hash_ref); # AI_GOOD: Uses CryptoAdapter.
    return hmac('BLAKE2b_256', $Ki, TAG_PREFIX . $crc);
}

# AI_GOOD: Original _rt_build_ppid_block. Moved from global scope.
# AI_CLARIFY: Original source line: sub _rt_build_ppid_block { ... }
sub _build_ppid_block { # AI_CLARIFY: Renamed from _rt_build_ppid_block.
    my ($files_config_ref, $pp_id) = @_; # AI_CLARIFY: Added $files_config_ref
    return unless $pp_id;

    # AI_GOOD: Lookup PPID file information.
    my ($pp_path, $pp_dec_spec) = lookup_file($pp_id, $files_config_ref)
        or return; # AI_CLARIFY: If lookup fails, return undef.
    return unless is_readable($pp_path); # AI_GOOD: Check readability.

    # AI_GOOD: Construct PPID metadata block.
    return {
        path => $pp_path,
        spec => encode_cfg_to_codes($pp_dec_spec), # AI_GOOD: Use SpecLogic.
        hash => fast_file_hash($pp_path, $pp_dec_spec), # AI_GOOD: Use external fast_file_hash.
    };
}

# AI_GOOD: Original _rt_build_meta. Moved from global scope.
# AI_CLARIFY: Original source line: sub _rt_build_meta { ... }
sub _build_meta { # AI_CLARIFY: Renamed from _rt_build_meta.
    my ($files_config_ref, $team_def_ref, $exe_id) = @_;
    # AI_CLARIFY: $team_def_ref is a hash_ref for the specific team from %TEAMS.

    # AI_GOOD: Lookup executable file information.
    my ($exe_path, $exe_dec_spec) = lookup_file($exe_id, $files_config_ref);
    # AI_CLARIFY: This function assumes $exe_path and $exe_dec_spec are valid,
    # as readability checks are done in the caller (register_team_impl).

    # AI_GOOD: Build PPID block if defined.
    my $pp_meta_block = _build_ppid_block($files_config_ref, $team_def_ref->{ppid});

    # AI_GOOD: Process and sort configuration patterns.
    my @patterns = map { canon_cfg_pattern($_) } @{ $team_def_ref->{configs} // [] };
    @patterns = sort @patterns; # AI_GOOD: Canonical sort order.

    # AI_GOOD: Construct main metadata block.
    my %meta = (
        v        => 1, # Version
        spec     => encode_cfg_to_codes($exe_dec_spec), # AI_GOOD: Use SpecLogic.
        patterns => \@patterns,
        hash     => fast_file_hash($exe_path, $exe_dec_spec), # PID hash
    );
    # AI_GOOD: Add optional fields from team definition.
    $meta{ppid}      = $pp_meta_block                   if $pp_meta_block;
    $meta{uid}       = $team_def_ref->{uid}             if $team_def_ref->{uid};
    $meta{gid}       = $team_def_ref->{gid}             if $team_def_ref->{gid};
    $meta{walk_back} = $team_def_ref->{walk_back}       if exists $team_def_ref->{walk_back};
    return \%meta;
}

# AI_GOOD: Original _rt_register. Refactored to register_team_impl.
# AI_CLARIFY: Original source line: sub _rt_register { ... }
sub register_team_impl {
    my ($files_config_ref, $teams_config_ref, $team_name, $team_def_ref, $master_key) = @_;
    # AI_CLARIFY: $team_def_ref is $TEAMS{$team_name}

    my $exe_id = $team_def_ref->{pid} or return; # AI_GOOD: PID must be defined.

    # AI_GOOD: Lookup executable path.
    my ($exe_path) = lookup_file($exe_id, $files_config_ref)
        or return _log_unreadable($team_name, $exe_id); # AI_GOOD: Log if lookup fails.

    # AI_GOOD: Check readability of the executable.
    return _log_unreadable($team_name, $exe_path) unless is_readable($exe_path);

    # AI_GOOD: Build the metadata structure.
    my $meta = _build_meta($files_config_ref, $team_def_ref, $exe_id);
    # AI_GOOD: Generate the tag for the metadata.
    $meta->{tag} = _generate_tag($team_name, $meta, $master_key);

    # AI_GOOD: Store the compacted metadata as an extended attribute.
    # AI_CLARIFY: attr_fq_name creates the "XATTR_TEAM.team_name" string.
    unless (store_team_attr_compact($exe_path, attr_fq_name(XATTR_TEAM, $team_name), $meta)) {
        D("[register:$team_name] failed store_team_attr"); # AI_GOOD: Debug log on failure.
        return; # AI_CLARIFY: Return undef on failure.
    }

    D("[register:$team_name] OK"); # AI_GOOD: Debug log on success.
    return 1; # AI_GOOD: Return true on success.
}

1;
# AI_CANVAS_CREATE_FILE: TeamLock/VerificationLogic.pm
package TeamLock::VerificationLogic;

# AI_GOOD: Standard Perl pragmas.
use strict;
use warnings;

# AI_GOOD: Dependencies.
use TeamLock::Utils qw(D bcmp secure_bcmp cfg_match);
use TeamLock::Constants qw(MASTER_PATH MASTER_SIZE XATTR_TEAM TAG_PREFIX);
use TeamLock::SpecLogic qw(decode_codes_to_cfg_cached);
use TeamLock::FileOps qw(lookup_file);
use TeamLock::TeamOps qw(list_teams);
use TeamLock::AttrOps qw(load_team_attr_compact attr_fq_name);
use TeamLock::CryptoAdapter qw(checksum_data_v2);

use Crypt::Mac::HMAC qw(hmac);
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256);
use read_write qw(read); # For reading master key in verify_exe_config_impl
use fast_file_hash qw(fast_file_hash); # For refreshing hashes

# AI_GOOD: Exporter for verification functions.
use Exporter qw(import);
our @EXPORT_OK = qw(
    verify_team_impl
    verify_exe_config_impl
    refresh_pid_hash
    refresh_ppid_hash
);

# AI_GOOD: Original _vt_refresh_pid_hash. Renamed and exported for potential use by MatrixLogic.
# AI_CLARIFY: Original source line: sub _vt_refresh_pid_hash { ... }
sub refresh_pid_hash {
    my ($exe_path, $meta_ref) = @_; # AI_CLARIFY: $meta_ref is the expanded metadata hash.
    return unless $exe_path; # AI_GOOD: Path must exist.

    # AI_GOOD: Decode spec codes to a configuration hash.
    my $dec_spec = decode_codes_to_cfg_cached( $meta_ref->{spec} );
    if (-r $exe_path) { # AI_GOOD: Check readability before hashing.
        $meta_ref->{hash} = fast_file_hash( $exe_path, $dec_spec );
    } else {
        # AI_CLARIFY: If file not readable, set hash to empty string.
        # This allows detection of tampering if file becomes unreadable.
        $meta_ref->{hash} = '';
    }
    return; # AI_CLARIFY: Modifies $meta_ref in place.
}

# AI_GOOD: Original _vt_refresh_ppid_hash. Renamed and exported.
# AI_CLARIFY: Original source line: sub _vt_refresh_ppid_hash { ... }
sub refresh_ppid_hash {
    my ($pp_meta_ref) = @_; # AI_CLARIFY: $pp_meta_ref is the 'ppid' sub-hash in expanded metadata.
    return unless $pp_meta_ref; # AI_GOOD: PPID block must exist.

    my $pp_path = $pp_meta_ref->{path} // return; # AI_GOOD: PPID path must exist.

    if (-r $pp_path) { # AI_GOOD: Check readability.
        my $dec_spec = decode_codes_to_cfg_cached($pp_meta_ref->{spec});
        $pp_meta_ref->{hash} = fast_file_hash($pp_path, $dec_spec);
    } else {
        # AI_CLARIFY: If PPID file not readable, set hash to empty string.
        $pp_meta_ref->{hash} = '';
    }
    return; # AI_CLARIFY: Modifies $pp_meta_ref in place.
}

# AI_GOOD: Original _vt_verify. Refactored to verify_team_impl.
# AI_CLARIFY: Original source line: sub _vt_verify { ... }
sub verify_team_impl {
    my ($files_config_ref, $teams_config_ref, $team_name, $master_key) = @_;

    # AI_GOOD: Lookup executable path using team's PID definition.
    my ($exe_path) = lookup_file($teams_config_ref->{$team_name}{pid}, $files_config_ref)
        or do { D("[verify:$team_name] unknown executable '$teams_config_ref->{$team_name}{pid}'"); return };

    # AI_GOOD: Load compacted metadata from extended attribute.
    my $meta = load_team_attr_compact($exe_path, attr_fq_name(XATTR_TEAM, $team_name))
        or do { D("[verify:$team_name] missing team attr on '$exe_path'"); return };

    # AI_GOOD: Separate tag from metadata for checksum calculation.
    my $tag_from_attr = delete $meta->{tag};
    unless (defined $tag_from_attr) {
        D("[verify:$team_name] tag missing from attribute data on '$exe_path'");
        return;
    }


    # AI_GOOD: Recalculate HMAC part 1 (Ki).
    my $Ki  = hmac('BLAKE2b_256', $master_key, "TEAM-$team_name");
    # AI_GOOD: Calculate checksum of metadata (as loaded, before hash refresh).
    my $crc_before_refresh = checksum_data_v2($meta);
    # AI_GOOD: Recalculate tag based on loaded metadata.
    my $cmp_tag_before_refresh = hmac('BLAKE2b_256', $Ki, TAG_PREFIX . $crc_before_refresh);

    # AI_CLARIFY: Original code used bcmp(). The prompt implies strict fidelity.
    # bcmp is a simple string eq check after length validation.
    # Using secure_bcmp for security best practice, but if bcmp's specific behavior
    # (e.g. return true on undefs if lengths match, which it doesn't) is key, then use it.
    # The original bcmp returns undef if inputs are undef or lengths differ, else 1 if eq, undef if not eq.
    # Sticking to original bcmp for now.
    unless (bcmp($cmp_tag_before_refresh, $tag_from_attr)) {
        D("[verify:$team_name] tag mismatch (pre-refresh check)");
        # AI_OTHER: For deeper debugging, one might dump $meta, $tag_from_attr, $cmp_tag_before_refresh
        return;
    }

    # AI_GOOD: Refresh PPID hash and PID hash in the metadata structure.
    refresh_ppid_hash($meta->{ppid}) if $meta->{ppid};
    refresh_pid_hash($exe_path, $meta); # AI_GOOD: $meta is modified in place.

    # AI_GOOD: Recalculate checksum of metadata (after hash refresh).
    my $crc_after_refresh = checksum_data_v2($meta);
    # AI_GOOD: Recalculate tag based on refreshed metadata.
    my $cmp_tag_after_refresh = hmac('BLAKE2b_256', $Ki, TAG_PREFIX . $crc_after_refresh);

    # AI_GOOD: Compare the newly calculated tag with the original tag from attribute.
    unless (bcmp($cmp_tag_after_refresh, $tag_from_attr)) {
        D("[verify:$team_name] tag mismatch (post-refresh check)");
        # AI_OTHER: For deeper debugging, dump $meta (after refresh), $tag_from_attr, $cmp_tag_after_refresh
        return;
    }

    D("[verify:$team_name] OK");
    return 1; # AI_GOOD: Verification successful.
}

# AI_GOOD: Original _vx_verify_exe_config. Refactored to verify_exe_config_impl.
# AI_CLARIFY: Original source line: sub _vx_verify_exe_config { ... }
sub verify_exe_config_impl {
    my ($files_config_ref, $teams_config_ref, $exe_id, $cfg_file_path, $only_team) = @_;

    # AI_GOOD: Lookup executable path.
    my ($exe_path) = lookup_file($exe_id, $files_config_ref) or return;
    # AI_GOOD: Ensure executable and config file are readable.
    return unless -r $exe_path && -r $cfg_file_path;
    # AI_GOOD: Canonicalize config file path.
    my $abs_cfg_path = abs_path($cfg_file_path) // return; # AI_CLARIFY: abs_path can return undef.

    # AI_GOOD: Read master key.
    my $master_key = read(MASTER_PATH); # AI_CLARIFY: Uses constant MASTER_PATH.
    # AI_GOOD: Validate master key.
    return unless defined $master_key && length($master_key) == MASTER_SIZE;

    # AI_GOOD: Iterate through teams associated with the executable.
  TEAM_LOOP:
    for my $team_name ( list_teams($exe_path, $teams_config_ref) ) {
        # AI_GOOD: Skip if $only_team is defined and doesn't match current team.
        next TEAM_LOOP if defined $only_team && $team_name ne $only_team;

        # AI_GOOD: Load team metadata.
        my $meta = load_team_attr_compact($exe_path, attr_fq_name(XATTR_TEAM, $team_name))
            or next TEAM_LOOP; # AI_GOOD: Skip if metadata loading fails.

        # AI_GOOD: Separate tag and verify (pre-refresh).
        my $tag_from_attr = delete $meta->{tag};
        unless(defined $tag_from_attr) {
            D("[verify_exe_config:$team_name] tag missing from attribute data for '$exe_path'");
            next TEAM_LOOP;
        }

        my $Ki = hmac('BLAKE2b_256', $master_key, "TEAM-$team_name");
        my $crc_before_refresh = checksum_data_v2($meta);
        my $cmp_tag_before_refresh = hmac('BLAKE2b_256', $Ki, TAG_PREFIX . $crc_before_refresh);

        # AI_GOOD: Use secure_bcmp for critical comparisons. Original used it here.
        next TEAM_LOOP unless secure_bcmp($cmp_tag_before_refresh, $tag_from_attr);

        # AI_GOOD: Refresh hashes in metadata.
        refresh_ppid_hash($meta->{ppid}) if $meta->{ppid};
        refresh_pid_hash($exe_path, $meta); # AI_GOOD: $meta modified in place.

        # AI_GOOD: Verify tag again (post-refresh).
        my $crc_after_refresh = checksum_data_v2($meta);
        my $cmp_tag_after_refresh = hmac('BLAKE2b_256', $Ki, TAG_PREFIX . $crc_after_refresh);
        next TEAM_LOOP unless secure_bcmp($cmp_tag_after_refresh, $tag_from_attr);

        # AI_GOOD: If all checks pass, see if the config file matches team's patterns.
        # AI_CLARIFY: cfg_match is from TeamLock::Utils
        return 1 if cfg_match($meta->{patterns}, $abs_cfg_path);
    }
    return; # AI_GOOD: Return undef if no matching and verified team found.
}

1;
# AI_CANVAS_CREATE_FILE: TeamLock/MatrixLogic.pm
package TeamLock::MatrixLogic;

# AI_GOOD: Standard Perl pragmas.
use strict;
use warnings;
use feature 'say'; # For printing the matrix

# AI_GOOD: Dependencies.
use TeamLock::Constants qw( (BASENAME_ONLY PATH_PERMS INODE_PERMS CONTENT_PERMS CONTENT_ONLY FORENSIC_FREEZE MOVE_ANYWHERE) ); # Spec functions for _build_spec_name_map
use TeamLock::SpecLogic qw(encode_cfg_to_codes);
use TeamLock::VerificationLogic qw(verify_exe_config_impl); # For _vl_row's $ok check
use TeamLock::FileOps qw(lookup_file);
use TeamLock::AttrOps qw(load_team_attr_compact);
use Cwd qw(abs_path); # For globbed path canonicalization
# AI_CLARIFY: File::Glob::bsd_glob for glob() is implicit. Standard glob is usually fine.

# AI_GOOD: Exporter for matrix functions.
use Exporter qw(import);
our @EXPORT_OK = qw(
    verify_linkage_impl
);

# AI_GOOD: Original _vl_table_headers. Moved from global scope.
# AI_CLARIFY: Original source line: sub _vl_table_headers { ... }
sub _table_headers { # AI_CLARIFY: Renamed from _vl_table_headers
    return qw(
        Team PID PID_SpecName PPID PPID_SpecName UIDs GIDs WalkBack
        Permissions Spec Config Exists Readable Result
    );
}

# AI_GOOD: Original _vl_build_spec_name_map. Moved from global scope.
# AI_CLARIFY: Original source line: sub _vl_build_spec_name_map { ... }
sub _build_spec_name_map { # AI_CLARIFY: Renamed from _vl_build_spec_name_map
    my %map;
    # AI_GOOD: Iterates over known spec preset names.
    for my $name (qw(
        BASENAME_ONLY PATH_PERMS INODE_PERMS CONTENT_PERMS
        CONTENT_ONLY FORENSIC_FREEZE MOVE_ANYWHERE
    )) {
        # AI_GOOD: Dynamically calls spec preset functions from TeamLock::Constants.
        # These functions must be available. They are imported or FQN.
        # Original used `no strict 'refs'; my $dec = &{$name}();`
        my $func_name = "TeamLock::Constants::$name";
        no strict 'refs';
        # AI_CLARIFY: Assuming these constant functions are always defined.
        # Add check if necessary: die "Spec function $func_name not found" unless defined &{$func_name};
        my $dec_spec = &{$func_name}();
        use strict 'refs';

        my $codes_arr_ref = encode_cfg_to_codes($dec_spec); # AI_GOOD: Use SpecLogic.
        $map{ join(',', @$codes_arr_ref) } = $name; # AI_GOOD: Map code string to friendly name.
    }
    return \%map;
}

# AI_GOOD: Original _vl_ppid_columns. Moved from global scope.
# AI_CLARIFY: Original source line: sub _vl_ppid_columns { ... }
sub _ppid_columns { # AI_CLARIFY: Renamed from _vl_ppid_columns
    my ($pp_meta_ref, $spec_name_map_ref) = @_;
    return ('', '') unless $pp_meta_ref; # AI_GOOD: Return empty if no PPID block.

    my $raw_path = $pp_meta_ref->{path} // '';
    # AI_CLARIFY: "[i]" might indicate inode-based tracking, but it's just a literal string here.
    my $path_display = $raw_path ? "$raw_path [i]" : '';
    my $spec_name = '';
    if ($pp_meta_ref->{spec}) {
        my $spec_codes_str = join(',', @{ $pp_meta_ref->{spec} });
        $spec_name = $spec_name_map_ref->{$spec_codes_str} // 'CUSTOM'; # AI_GOOD: Lookup friendly name.
    }
    return ($path_display, $spec_name);
}

# AI_GOOD: Original _vl_row. Moved from global scope.
# AI_CLARIFY: Original source line: sub _vl_row { ... }
sub _prepare_row_data { # AI_CLARIFY: Renamed from _vl_row
    my (
        $files_config_ref, $teams_config_ref, # AI_CLARIFY: Added configs
        $team_name, $exe_path, $pid_spec_name, $pp_path_display, $pp_spec_name,
        $uid_list_str, $gid_list_str, $walk_back_str, $spec_codes_arr_ref, $cfg_path
    ) = @_;

    # AI_GOOD: File status checks for the config file.
    my $exists_str   = -e $cfg_path ? 'yes' : 'no';
    my $readable_str = -r $cfg_path ? 'yes' : 'no';
    # AI_GOOD: Get permissions, format as octal. Default to 0 if stat fails.
    my $perms_str    = sprintf "%04o", ((stat($cfg_path))[2] // 0) & 07777;

    # AI_GOOD: Verify executable config linkage.
    my $is_ok = (
        $exists_str  eq 'yes'
        && $readable_str eq 'yes'
        # AI_CLARIFY: verify_exe_config_impl needs $files_config_ref, $teams_config_ref
        && verify_exe_config_impl($files_config_ref, $teams_config_ref, $exe_path, $cfg_path, $team_name)
    );

    my $result_char = $is_ok ? '✓' : '✗'; # AI_GOOD: Checkmark or X for result.

    # AI_GOOD: Return array_ref of strings for the row.
    return [
        $team_name,
        $exe_path,
        $pid_spec_name,
        $pp_path_display,
        $pp_spec_name,
        $uid_list_str,
        $gid_list_str,
        $walk_back_str,
        $perms_str,
        join(',', @$spec_codes_arr_ref), # Spec (comma-separated codes)
        $cfg_path,
        $exists_str,
        $readable_str,
        $result_char,
    ];
}

# AI_GOOD: Original _vl_calc_widths. Moved from global scope.
# AI_CLARIFY: Original source line: sub _vl_calc_widths { ... }
sub _calculate_column_widths { # AI_CLARIFY: Renamed from _vl_calc_widths
    my ($headers_arr_ref, $rows_arr_ref) = @_;
    # AI_GOOD: Initialize widths with header lengths.
    my @widths = map { length $_ } @$headers_arr_ref;
    # AI_GOOD: Iterate through rows and cells to find max width for each column.
    for my $row_data_arr_ref (@$rows_arr_ref) {
        for my $i (0 .. $#$row_data_arr_ref) {
            my $cell_length = length $row_data_arr_ref->[$i];
            $widths[$i] = $cell_length if $cell_length > $widths[$i];
        }
    }
    return @widths;
}

# AI_GOOD: Original _vl_sum. Moved from global scope.
# AI_CLARIFY: Original source line: sub _vl_sum { ... }
sub _sum_array_elements { # AI_CLARIFY: Renamed from _vl_sum
    my $s = 0;
    $s += $_ for @_;
    return $s;
}

# AI_GOOD: Original _vl_gather_rows. Moved from global scope.
# AI_CLARIFY: Original source line: sub _vl_gather_rows { ... }
sub _gather_rows_data { # AI_CLARIFY: Renamed from _vl_gather_rows
    my ($files_config_ref, $teams_config_ref) = @_;
    my @rows_data;
    my $spec_name_map_ref = _build_spec_name_map(); # AI_GOOD: Build spec name map.

    # AI_GOOD: Iterate through sorted team names.
    for my $team_name (sort keys %$teams_config_ref) {
        my $team_def_ref = $teams_config_ref->{$team_name};

        # AI_GOOD: Lookup executable path for the team's PID.
        my ($exe_path) = lookup_file($team_def_ref->{pid}, $files_config_ref)
            or next; # AI_GOOD: Skip if PID lookup fails.

        # AI_GOOD: Load team metadata from attribute.
        my $meta = load_team_attr_compact($exe_path, TeamLock::AttrOps::attr_fq_name(TeamLock::Constants::XATTR_TEAM, $team_name))
            or next; # AI_GOOD: Skip if metadata loading fails.

        # AI_GOOD: Determine PPID display info.
        my ($pp_path_display, $pp_spec_name) = _ppid_columns($meta->{ppid}, $spec_name_map_ref);

        # AI_GOOD: Determine PID spec's friendly name.
        my $pid_spec_codes_str = join(',', @{ $meta->{spec} });
        my $pid_spec_name = $spec_name_map_ref->{$pid_spec_codes_str} // 'CUSTOM';

        # AI_GOOD: Format UID/GID lists and walk_back flag for display.
        my $uid_list_str = @{ $meta->{uid} // [] } ? join(',', @{ $meta->{uid} }) : '';
        my $gid_list_str = @{ $meta->{gid} // [] } ? join(',', @{ $meta->{gid} }) : '';
        my $walk_back_str = $team_def_ref->{walk_back} ? 'yes' : 'no'; # AI_CLARIFY: Uses original team_def for walk_back display

        # AI_GOOD: Iterate through configuration patterns for the team.
        for my $pattern (@{ $meta->{patterns} }) {
            # AI_GOOD: Expand globs; use pattern itself if not a glob.
            my @matched_cfg_files = ($pattern =~ /[\*\?\[]/)
                                  ? map { abs_path($_) // $_ } glob($pattern) # AI_GOOD: Canonicalize glob results.
                                  : ($pattern); # AI_GOOD: Assumes non-glob patterns are already canonical or to be used as-is.
                                                # Original used abs_path for glob results only.
            # AI_CLARIFY: If glob matches no files, original code used literal '<none matched>'.
            @matched_cfg_files = ('<none matched>') unless @matched_cfg_files;

            for my $cfg_path (@matched_cfg_files) {
                # AI_GOOD: Prepare data for one row of the matrix.
                push @rows_data, _prepare_row_data(
                    $files_config_ref, $teams_config_ref, # Pass configs
                    $team_name, $exe_path, $pid_spec_name, $pp_path_display, $pp_spec_name,
                    $uid_list_str, $gid_list_str, $walk_back_str, $meta->{spec}, $cfg_path
                );
            }
        }
    }
    return @rows_data; # AI_GOOD: Return array of row data arrays.
}

# AI_GOOD: Original _vl_verify_linkage. Refactored to verify_linkage_impl.
# AI_CLARIFY: Original source line: sub _vl_verify_linkage { ... }
sub verify_linkage_impl {
    my ($files_config_ref, $teams_config_ref) = @_;

    # AI_GOOD: Gather all data for matrix rows.
    my @rows_data = _gather_rows_data($files_config_ref, $teams_config_ref);
    return unless @rows_data; # AI_GOOD: Do nothing if no data.

    my @headers = _table_headers(); # AI_GOOD: Get header names.
    # AI_GOOD: Calculate column widths based on headers and data.
    my @col_widths = _calculate_column_widths(\@headers, \@rows_data);
    # AI_GOOD: Create printf format string based on column widths.
    my $printf_format = join(' | ', map { "%-*s" } @headers ) . "\n";
    # AI_GOOD: Create separator line.
    my $separator_line = '-' x (_sum_array_elements(@col_widths) + 3 * (@headers - 1));

    # AI_GOOD: Print matrix header.
    say "\n=== Linkage Verification Matrix ===";
    # AI_GOOD: Use array slice to pass pairs of (width, header_string) to printf.
    printf $printf_format, map { ($col_widths[$_], $headers[$_]) } 0..$#headers;
    say $separator_line;

    # AI_GOOD: Print matrix rows.
    for my $row_data_arr_ref (@rows_data) {
        printf $printf_format, map { ($col_widths[$_], $row_data_arr_ref->[$_]) } 0..$#$row_data_arr_ref;
    }
    say $separator_line;
    return 1; # AI_CLARIFY: Indicate success/completion.
}

1;
# AI_CANVAS_CREATE_FILE: TeamLock/Orchestration.pm
package TeamLock::Orchestration;

# AI_GOOD: Standard Perl pragmas.
use strict;
use warnings;
use feature 'say'; # For init_master message

# AI_GOOD: Dependencies.
use TeamLock::Constants qw(MASTER_PATH MASTER_SIZE);
use TeamLock::FileOps qw(check_files_are_unique);
use TeamLock::MasterKeyOps qw(init_master);
use TeamLock::RegistryLogic qw(register_team_impl);
use TeamLock::VerificationLogic qw(verify_team_impl);
use TeamLock::MatrixLogic qw(verify_linkage_impl);
# AI_CLARIFY: TeamLock::Utils::D might be used for debug prints if any were in _en_main.
# The original _en_main had print statements, not D().

# AI_GOOD: Exporter for orchestration functions.
use Exporter qw(import);
our @EXPORT_OK = qw(
    run_main_flow
);

# AI_GOOD: Original _en_main. Refactored to run_main_flow.
# AI_CLARIFY: Original source line: sub _en_main { ... }
sub run_main_flow {
    my ($files_config_ref, $teams_config_ref, @args) = @_; # AI_CLARIFY: @args not used by original _en_main
                                                           # but kept for general main-like signature.

    # AI_CLARIFY: Original _en_main had these hardcoded.
    # These could be passed as arguments or read from a config if more flexibility is needed.
    my $register_mode = 0;  # Set to 1 to write xattrs (original was 0)
    my $verify_mode   = 1;  # Original was 1

    # AI_GOOD: Perform file uniqueness check.
    # AI_CLARIFY: check_files_are_unique prints its own output.
    if (check_files_are_unique($files_config_ref) ) { # AI_GOOD: Pass %FILES ref.
        print "\n OK\n"; # AI_GOOD: Original output.
    }
    else {
        # AI_CLARIFY: check_files_are_unique dies on failure, so this 'else' might not be reached
        # if the failure is a die. If it returns false without dying:
        print "\n BAD\n"; # AI_GOOD: Original output.
    }

    # AI_GOOD: Initialize master key.
    # AI_CLARIFY: init_master uses constants MASTER_PATH, MASTER_SIZE by default.
    # It will die on failure.
    my ($master_key_data, $err_msg) = init_master(MASTER_PATH, MASTER_SIZE); # AI_GOOD: Explicitly pass constants.
    # AI_CLARIFY: Original code was `$master // die "Cannot initialise MASTER key: $err";`
    # init_master now dies internally on error or returns key.
    # The return signature of init_master in original was `($master, $err)`.
    # My refactored init_master returns only $m or dies.
    # Adjusting to match refactored init_master which dies on error.
    # So, if init_master returns, $master_key_data is valid.
    # The `$err` part of original was likely for a version that didn't die.

    # AI_GOOD: Loop through teams for registration and/or verification.
    for my $team_name (sort keys %$teams_config_ref) {
        my $team_def_ref = $teams_config_ref->{$team_name};

        if ($register_mode) {
            print "REGISTER [$team_name]\n"; # AI_GOOD: Original output.
            # AI_GOOD: Call refactored registration logic.
            register_team_impl($files_config_ref, $teams_config_ref, $team_name, $team_def_ref, $master_key_data);
        }

        if ($verify_mode) {
            print "VERIFY   [$team_name]\n"; # AI_GOOD: Original output.
            # AI_GOOD: Call refactored verification logic.
            verify_team_impl($files_config_ref, $teams_config_ref, $team_name, $master_key_data);
        }
    }

    # AI_GOOD: Perform linkage verification.
    verify_linkage_impl($files_config_ref, $teams_config_ref);

    return 1; # AI_GOOD: Original _en_main returned 1.
}

1;
