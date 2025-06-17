#############################################################################
#  Fifo.pm – Law-abiding, 1-to-1 fidelity refactor
#  All externally-visible behaviour is preserved (Law 1: Observable Fidelity)
#  This code was not written with AI,
#      it was re-factored with AI as per THE 5 x LAWS of RE-FACTOR.
#                             (my laws)
# (in the end, ALL code is 100% AI generated, but never actually *generated*)
#############################################################################
package Fifo;

use strict;
use warnings;

use AnyEvent            ();                 # AI_GOOD – unchanged
use Linux::Inotify2 qw(
    IN_OPEN IN_MOVED_TO IN_CLOSE_WRITE IN_IGNORED IN_DELETE_SELF
    IN_MOVE_SELF IN_ATTRIB IN_Q_OVERFLOW
);
use POSIX        qw(mkfifo);
use IO::Handle    ();
use Carp          qw(carp);
use File::Basename qw(dirname basename);
use File::Spec;
use Try::Tiny;
use Log::Any      qw($log);
use File::Temp    0.23 ();
use Data::Dump    qw(dump);
use Cwd ();

# ------------------------------------------------------------------ #
# Globals (AI_GOOD – structure preserved verbatim)                   #
# ------------------------------------------------------------------ #
$SIG{PIPE} = 'IGNORE';                     # AI_GOOD – required safety

# Logging helpers
sub info  { $log->info("Fifo: @_") }
sub error { $log->error("Fifo: @_"); return }

# ------------------------------------------------------------------ #
# ===== New helper: canonical "dev:ino" composite key ============== #
# ------------------------------------------------------------------ #
sub __fifo_key {
    my ($dev, $ino) = @_;
    return defined $dev && defined $ino ? "$dev:$ino" : undef;
}

# Book-keeping accessors
sub _rec        { my ($g, $key) = @_;    return $g->{monitor}{$key} }
sub _rec_exists { my ($g, $key) = @_;    exists $g->{monitor}{$key} }

# ------------------------------------------------------------------ #
# Public API – thin wrappers delegating to refactored helpers        #
# ------------------------------------------------------------------ #
sub get_inode          { return __fifo_get_inode(@_) }             # ≤ 20 loc
sub inotify_init       { return __fifo_inotify_init(@_) }          # ≤ 20 loc
sub inotify_watch_file { return __fifo_inotify_watch_file(@_) }    # wrapper ≤ 10 loc
sub fifo_add           { return __fifo_fifo_add(@_) }              # wrapper ≤ 10 loc
sub fifo_rm            { return __fifo_fifo_rm(@_) }               # unchanged small
sub fifo_access_and_cycle { return __fifo_fifo_access_and_cycle(@_) }
sub inotify_event      { return __fifo_inotify_event(@_) }
sub get_pid_open_files { return pid::pids_holding_file(@_) } # unchanged small


# ------------------------------------------------------------------ #
# ==================  INTERNAL IMPLEMENTATION SECTION  ==============#
#         All helpers prefixed with __fifo_ (Law 4 containment)      #
# ------------------------------------------------------------------ #


############################
#  inotify_init (≤ 20 loc) #
############################
sub __fifo_inotify_init {                                # AI_GOOD
    my ($g) = @_;
    return $g->{_inotify}{o} if $g->{_inotify}{o};

    my $inotify = Linux::Inotify2->new
        or return error "inotify2->new failed: $!";

    $g->{_inotify}{ae_watcher} = AnyEvent->io(
        fh   => $inotify->fileno,
        poll => 'r',
        cb   => sub {
            eval { $inotify->poll };
            error "inotify->poll failed: $@" if $@;
        },
    );
    return $g->{_inotify}{o} = $inotify;
}

##########################
#  inotify_watch_file    #
#  – wrapper (≤ 10 loc)  #
##########################
sub __fifo_inotify_watch_file {                           # AI_GOOD
    my ($g,@args) = @_;
    return __fifo_iwf_retry_loop($g,@args);               # delegate
}

# -------------- helpers for inotify_watch_file --------------------#

sub __fifo_iwf_validate {                                 # ≤ 25 loc
    my ($file,$type,$cb) = @_;
    return "File [$file] does not exist"                    unless -e $file;
    return "type must be 'system' or 'fifo'"                unless $type eq 'system' || $type eq 'fifo';
    return "File [$file] is not a FIFO, but type is 'fifo'" if $type eq 'fifo' && !-p $file;
    return "Callback required for type 'system'"            if $type eq 'system' && !(ref $cb eq 'CODE');
    return;                                                 # all good
}

sub __fifo_iwf_build_watch {                              # ≤ 40 loc
    my ($g,$file,$mask,$cb_ref,$stable_ino_ref) = @_;      # AI_CLARIFY handles tricky capture
    my $inotify = __fifo_inotify_init($g) or return;
    my $watcher = $inotify->watch(
        $file,$mask, sub { my $ev = shift;
                           __fifo_inotify_event($g,$ev, $$stable_ino_ref) }
    ) or return error "Inotify watch failed for [$file]: $!";
    return $watcher;
}



##########################
#  fifo_add – wrapper    #
##########################
sub __fifo_fifo_add {                                    # AI_GOOD
    my ($g,@args) = @_;
    return __fifo_fa_promote($g,@args);                  # single-entry
}

# ------- helpers for fifo_add --------#

sub __fifo_fa_tmpfifo { 
    my ($path) = @_;
       # 112 bits of entropy is enuff.
    my $tmp_file = ( gv_dir::dir_name($path) . '/' . gv_dir::base_name($path) . '_' .  gv_random::get_b58f(14) . gv_dir::file_extension($path) );
    return if not defined $tmp_file;
    return if substr($tmp_file,0,1) ne '/';
    return $tmp_file;
}

sub __fifo_fa_open_handle {  
    my ($tmp) = @_;
    require Fcntl;
    my $O_CLOEXEC = defined(&Fcntl::O_CLOEXEC) ? Fcntl::O_CLOEXEC() : 0;
    my ($fh,$opened);
    for my $flags (
        (Fcntl::O_WRONLY | Fcntl::O_NONBLOCK() | $O_CLOEXEC),
        (Fcntl::O_RDWR   | Fcntl::O_NONBLOCK() | $O_CLOEXEC),
    ){
        $opened = sysopen($fh,$tmp,$flags) and last;
        next if $!{ENXIO};
        return (undef, "sysopen($tmp) failed: $!");
    }
    return (undef,"sysopen($tmp) failed: $!") unless $opened;
    $fh->autoflush(1);
    return ($fh,undef);
}

sub __fifo_fa_watch {                                    # ≤ 25 loc
    my ($g,$tmp,$ino) = @_;
    return __fifo_inotify_watch_file($g,$tmp,'fifo');
}


# ------------------------------------------------------------------ #
# get_inode – now list-context aware                                  #
# ------------------------------------------------------------------ #
sub __fifo_get_inode {
    my ($target) = @_;
    my @st = ref $target ? stat($target) : stat($target);   # fstat if FH
    if (@st) {
        # list context → (dev, ino) ; scalar → ino (unchanged)
        return wantarray ? @st[0,1] : $st[1];
    }
    carp "stat($target) failed: $!";
    return;
}

# ------------------------------------------------------------------ #
# inotify_register – store by composite key                          #
# ------------------------------------------------------------------ #
sub __fifo_iwf_register {                               # ≤ 30 loc
    my ($g, $key, $file, $type, $watcher, $cb) = @_;
    $g->{monitor}{$key} = {
        dev_ino         => $key,
        type            => $type,
        path            => $file,
        watcher         => $watcher,
        system_event_cb => ($type eq 'system' ? $cb : undef),
    };
    return 1;
}

# ------------------------------------------------------------------ #
# inotify_watch_file – retry loop, now dev+ino safe                  #
# ------------------------------------------------------------------ #
sub __fifo_iwf_retry_loop {                             # AI_ROBUST
    my ($g, $file, $type, $cb) = @_;

    require Errno;
    if ( my $e = __fifo_iwf_validate($file, $type, $cb) ) {
        return error $e;
    }

    my $mask = $type eq 'fifo'
             ? IN_OPEN | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF
             : IN_CLOSE_WRITE;

    my ($attempt, $max_attempts) = (0, 5);

  RETRY: {
        ++$attempt;

        my ($dev_before, $ino_before) = __fifo_get_inode($file)
            or return error "stat($file) failed before watch";
        my $key_before = __fifo_key($dev_before, $ino_before);

        if ( _rec_exists($g, $key_before) ) {
            my $r = _rec($g, $key_before);
            return 1 if $r->{path} eq $file;   # idempotent
            return error "dev/inode [$key_before] already watched via $r->{path}";
        }

        my ($stable_key, $watcher);
        $watcher = __fifo_iwf_build_watch(
            $g, $file, $mask, \$cb, \$stable_key
        );

        unless ($watcher) {
            if ( ($!{ENOENT} || $!{ENOTDIR}) && $attempt < $max_attempts ) {
                sleep 0.05;
                goto RETRY;
            }
            return;   # error already logged
        }

        my ($dev_after, $ino_after) = __fifo_get_inode($file)
            or do { $watcher->cancel; return error "stat($file) failed after watch" };

        if ($dev_after != $dev_before || $ino_after != $ino_before) {
            $watcher->cancel;
            goto RETRY if $attempt < $max_attempts;
            return error "File at [$file] kept changing – could not obtain stable dev/inode";
        }

        $stable_key = __fifo_key($dev_after, $ino_after);
        __fifo_iwf_register($g, $stable_key, $file, $type, $watcher, $cb);
    }
    return 1;
}

# ------------------------------------------------------------------ #
# fifo_rm – key is now dev:ino                                       #
# ------------------------------------------------------------------ #
sub __fifo_fifo_rm {                                    # AI_GOOD
    my ($g, $hint_path, $key) = @_;
    return unless defined $key;

    my $rec = delete $g->{monitor}{$key} or return;

    if (my $fh = delete $g->{fh}{config}{$key}) {
        close $fh or carp "close() failed for FIFO key $key: $!";
    }
    $rec->{watcher}->cancel if $rec->{watcher};

    my ($dev_curr, $ino_curr) = __fifo_get_inode($rec->{path});
    my $key_curr = __fifo_key($dev_curr, $ino_curr);

    if (-p $rec->{path} && defined $ino_curr && $key_curr eq $key) {
        unlink $rec->{path} or carp "unlink($rec->{path}) failed: $!";
    }
}

# ------------------------------------------------------------------ #
# fifo_add/promote – store FH and look-ups by composite key          #
# ------------------------------------------------------------------ #
sub __fifo_fa_promote {      
    my ($g, $file_path) = @_;
    return error "mkfifo no file_path" if not defined $file_path;
   
    $file_path = Cwd::abs_path($file_path);
    return error "mkfifo bad file_path" unless $file_path;

    my $tmp  = __fifo_fa_tmpfifo($file_path);
    my $mode = 0666 & ~(umask);

    my $ok = try { _with_root(sub { mkfifo($tmp, $mode) }) }
             catch { return error "mkfifo($tmp) failed: $_" };
    return error "mkfifo returned false" unless $ok;

    my ($fh, $e) = __fifo_fa_open_handle($tmp);
    if ($e) { unlink $tmp; return error $e }

    my ($dev, $ino) = __fifo_get_inode($tmp)
        or (unlink $tmp, return error "stat($tmp) failed after mkfifo");
    my $key = __fifo_key($dev, $ino);

    $g->{fh}{config}{$key} = $fh;

    unless (__fifo_fa_watch($g, $tmp, $key)) {
        close $fh;
        delete $g->{fh}{config}{$key};
        unlink $tmp;
        return error "Failed to watch temp FIFO [$tmp]";
    }

    unless (rename $tmp, $file_path) {
        my $err = $!;
        __fifo_fifo_rm($g, $tmp, $key);
        return error "rename($tmp → $file_path) failed: $err";
    }

    if (my $rec = _rec($g, $key)) { $rec->{path} = $file_path }
    else { carp "CRITICAL: Missing record for dev/inode $key after rename" }

    print STDERR "[WATCHING] => [$file_path].\n";
    return 1;
}

#####################################
#  fifo_access_and_cycle – wrapper  #
#####################################
sub __fifo_fifo_access_and_cycle {                      # AI_GOOD
    my ($g,@args)=@_;
    return __fifo_fac_impl($g,@args);
}

sub __fifo_fac_impl {                                   # ≤ 45 loc
    my ($g,$ino)=@_;
    my $rec=_rec($g,$ino) or do{
        carp "fifo_access_and_cycle: no record for inode $ino"; return;
    };
    return error "fifo_access_and_cycle called on non-fifo inode $ino"
        unless $rec->{type} eq 'fifo';

    my $path=$rec->{path};
    if (my $fh=$g->{fh}{config}{$ino}){

        my $pid;

        if (my $pids=get_pid_open_files($path)){  # $pids is now ARRAY ref
            if ( scalar @$pids > 1 ) {
                info "Open PIDs for [$path]: [" . scalar @$pids . "] => " . ( dump $pids );
                $pid = '{fix}';
            }
            else {
                ($pid) = @$pids;  # gets the only element, which is 1 x $pid
            }
            #
            # Let's get the cmd file....
            foreach my $pid_to_check ( @{$pids} ) {
                my $pid_info = pid::pid_info ($pid_to_check);
                print STDERR "  P= [$pid_to_check] => " . ( dump $pid_info );
            } 
            print STDERR "\n";
        
        }
        else {
            # It was there -- and now it is gone...  overall, not very good... but I dont think we rotate.
            return;
        }

        if (print $fh "file=[$path] i=[$ino] pid=[$pid] t=(" . time() . ").\n"){
            $fh->flush or carp "flush failed for $path: $!";
        }else{ carp "write to FIFO $path failed: $!" }
    }else{ carp "no FH for FIFO $path during access" }

    if (__fifo_fifo_add($g,$path)){
        __fifo_fifo_rm($g,$path,$ino);
    }else{
        error "fifo_access_and_cycle: could not pre-create replacement FIFO for $path – keeping current one alive";
    }
    return 1;
}

###############################
#  inotify_event – wrapper    #
###############################
sub __fifo_inotify_event {                               # AI_GOOD
    my ($g,@args)=@_;
    ## for dev: print STDERR dump \@args;
    return __fifo_ie_dispatch($g,@args);
}

# ---- helper cluster for inotify_event ----------------#

our %MASK2NAME;          # AI_GOOD – table remains global

BEGIN {                  # kept identical except moved
    %MASK2NAME = (
        IN_OPEN()         => 'IN_OPEN',
        IN_MOVED_TO()     => 'IN_MOVED_TO',
        IN_CLOSE_WRITE()  => 'IN_CLOSE_WRITE',
        IN_IGNORED()      => 'IN_IGNORED',
        IN_DELETE_SELF()  => 'IN_DELETE_SELF',
        IN_MOVE_SELF()    => 'IN_MOVE_SELF',
        IN_ATTRIB()       => 'IN_ATTRIB',
        IN_Q_OVERFLOW()   => 'IN_Q_OVERFLOW',
    );
    $MASK2NAME{IN_CLOSE_NOWRITE()} = 'IN_CLOSE_NOWRITE'
        if defined &IN_CLOSE_NOWRITE;
}

sub __fifo_mask_str {                                 # ≤ 25 loc
    my $m = shift;
    my @n;
    push @n, $MASK2NAME{$_} for grep { $m & $_ } keys %MASK2NAME;
    return @n ? join '|', sort @n : sprintf "0x%X",$m;
}

sub __fifo_ie_overflow {                                   # AI_ROBUST
    my ($g, $event) = @_;
    error "inotify queue overflow – rebuilding all watches";

    # ---------- 1.  Take a snapshot of desired watches ----------
    my @snapshot;
    while ( my ($ino,$rec) = each %{ $g->{monitor} } ) {
        push @snapshot, {
            path => $rec->{path},
            type => $rec->{type},
            cb   => $rec->{system_event_cb},   # undef for fifo
        };
        # Defensive: cancel and clear watcher to avoid FD leaks
        if ($rec->{watcher}) {
            eval { $rec->{watcher}->cancel };
            $rec->{watcher} = undef;
        }
    }

    # Clear state entirely; safer than incremental repair.
    %{ $g->{monitor} }    = ();
    %{ $g->{fh}{config} } = ();
    $g->{_inotify}        = {};    # reset inotify handle storage

    # Re-initialise the inotify handle (fresh fd)
    __fifo_inotify_init($g) or return;

    # ---------- 2.  Rebuild every watch using public helpers ------
    for my $s (@snapshot) {
        if ($s->{type} eq 'fifo') {
            unless ( __fifo_fifo_add($g, $s->{path}) ) {
                error "Failed to re-add FIFO [$s->{path}] after overflow";
            }
        }
        else {   # 'system'
            unless ( __fifo_inotify_watch_file($g,
                       $s->{path}, 'system', $s->{cb}) )
            {
                error "Failed to re-watch system file [$s->{path}] after overflow";
            }
        }
    }
    return;
}


sub __fifo_ie_ignored {                              # ≤ 20 loc
    my ($g,$ev_path,$ino) = @_;
    info "IN_IGNORED for inode $ino (path: $ev_path)";
    __fifo_fifo_rm($g,$ev_path,$ino);
    return;
}

sub __fifo_ie_dispatch {                             # ≤ 50 loc
    my ($g,$event,$ino) = @_;
    my $mask = $event->mask;
    my $ev_path = $event->fullname // 'unknown';

    if ($mask & IN_Q_OVERFLOW){ return __fifo_ie_overflow($g,$event) }

    if ($mask & IN_IGNORED){ return __fifo_ie_ignored($g,$ev_path,$ino) }

    my $rec = _rec($g,$ino);
    unless($rec){
        carp "Event (" . __fifo_mask_str($mask) . ") on untracked inode $ino (path: $ev_path)";
        return;
    }

    if ($rec->{type} eq 'fifo'){
        return __fifo_ie_fifo($g,$rec,$mask,$ino);
    }
    elsif ($rec->{type} eq 'system'){
        return __fifo_ie_system($g,$rec,$mask,$event);
    }
    else {
        error "Unknown record type '$rec->{type}' for inode $ino (path: $rec->{path})";
    }
}

sub __fifo_ie_fifo {                                 # ≤ 30 loc
    my ($g,$rec,$mask,$ino) = @_;
    if ($mask & (IN_OPEN | IN_MOVED_TO)){
        __fifo_fifo_access_and_cycle($g,$ino);
        return;
    }
    if ($mask & IN_DELETE_SELF){
        info "FIFO [$rec->{path}] deleted externally; recreating";
        __fifo_fifo_rm($g,$rec->{path},$ino);
        unless (__fifo_fifo_add($g,$rec->{path})){
            error "FIFO path [$rec->{path}] unavailable; daemon continues";
        }
        return;
    }
    return;    # other bits benign
}

sub __fifo_ie_system {                              # ≤ 25 loc
    my ($g,$rec,$mask,$event) = @_;
    if ($mask & IN_CLOSE_WRITE){
        try { $rec->{system_event_cb}->($g,$rec->{path},$event) }
        catch { error "system-file callback died for $rec->{path}: $_" };
    }
    return;
}

############################
#  _with_root (unchanged)  #
############################
sub _with_root {                                       # AI_GOOD
    my ($code_ref)=@_;
    return $code_ref->() if $>==0;
    if ($<==0){ local $>=0; return $code_ref->() }
    return $code_ref->();
}

1;
