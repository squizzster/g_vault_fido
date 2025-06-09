############################################################################
#  Fifo.pm – Law-abiding, 1-to-1 fidelity refactor
#  All externally-visible behaviour is preserved (Law 1: Observable Fidelity)
############################################################################
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

# ------------------------------------------------------------------ #
# Globals (AI_GOOD – structure preserved verbatim)                   #
# ------------------------------------------------------------------ #
$SIG{PIPE} = 'IGNORE';                     # AI_GOOD – required safety

# Logging helpers
sub info  { $log->info("Fifo: @_") }
sub error { $log->error("Fifo: @_"); return }

# Book-keeping accessors
sub _rec        { my ($g,$ino)=@_;    return $g->{monitor}{$ino} }
sub _rec_exists { my ($g,$ino)=@_;    exists $g->{monitor}{$ino} }

# ------------------------------------------------------------------ #
# Public API – thin wrappers delegating to refactored helpers        #
# ------------------------------------------------------------------ #

sub get_inode          { return __fifo_get_inode(@_) }           # ≤ 20 loc

sub inotify_init       { return __fifo_inotify_init(@_) }        # ≤ 20 loc

sub inotify_watch_file { return __fifo_inotify_watch_file(@_) }  # wrapper ≤ 10 loc

sub fifo_add           { return __fifo_fifo_add(@_) }            # wrapper ≤ 10 loc

sub fifo_rm            { return __fifo_fifo_rm(@_) }             # unchanged small

sub fifo_access_and_cycle { return __fifo_fifo_access_and_cycle(@_) }

sub inotify_event      { return __fifo_inotify_event(@_) }

sub get_pid_open_files { return __fifo_get_pid_open_files(@_) }  # unchanged small


# ------------------------------------------------------------------ #
# ==================  INTERNAL IMPLEMENTATION SECTION  ==============#
#         All helpers prefixed with __fifo_ (Law 4 containment)      #
# ------------------------------------------------------------------ #

###########################
#  get_inode (≤ 20 loc)   #
###########################
sub __fifo_get_inode {                                   # AI_GOOD
    my ($target) = @_;
    my @st = ref $target ? stat($target) : stat($target);  # fstat if FH
    if (@st) { return $st[1] }                             # st_ino
    carp "stat($target) failed: $!";
    return;
}

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

sub __fifo_iwf_register {                                 # ≤ 30 loc
    my ($g,$ino,$file,$type,$watcher,$cb) = @_;
    $g->{monitor}{$ino} = {
        type            => $type,
        path            => $file,
        watcher         => $watcher,
        system_event_cb => ($type eq 'system' ? $cb : undef),
    };
    return 1;
}

sub __fifo_iwf_retry_loop {                               # ≤ 50 loc
    my ($g,$file,$type,$cb) = @_;

    if (my $err = __fifo_iwf_validate($file,$type,$cb)) { return error $err }

    my $mask = $type eq 'fifo'
        ? IN_OPEN | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF
        : IN_CLOSE_WRITE;

    my $attempt = 0;
  RETRY: {
        $attempt++;
        my $ino_before = __fifo_get_inode($file)
            or return error "stat($file) failed before watch";

        if (_rec_exists($g,$ino_before)) {
            my $r = _rec($g,$ino_before);
            return error "Inode [$ino_before] for [$file] is already watched (path: $r->{path})";
        }

        my $stable_ino;          # lexical captured by callback
        my $watcher = __fifo_iwf_build_watch($g,$file,$mask,\$cb,\$stable_ino)
            or return;           # error already logged

        my $ino_after = __fifo_get_inode($file)
            or do { $watcher->cancel; return error "stat($file) failed after watch" };

        if ($ino_after != $ino_before) {                  # inode raced
            $watcher->cancel;
            goto RETRY if $attempt < 5;                   # AI_GOOD – identical policy
            return error "Could not obtain stable inode for [$file]";
        }

        $stable_ino = $ino_after;
        __fifo_iwf_register($g,$stable_ino,$file,$type,$watcher,$cb);
    }
    return 1;
}

##########################
#  fifo_add – wrapper    #
##########################
sub __fifo_fifo_add {                                    # AI_GOOD
    my ($g,@args) = @_;
    return __fifo_fa_promote($g,@args);                   # single-entry
}

# ------- helpers for fifo_add --------#

sub __fifo_fa_tmpfifo {                                  # ≤ 25 loc
    my ($path) = @_;
    my $dir  = dirname($path);
    my $base = basename($path);
    my $tmpl = ".$base.XXXXXX";
    return File::Temp::tempnam($dir,$tmpl);
}

sub __fifo_fa_open_handle {                              # ≤ 40 loc
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

sub __fifo_fa_promote {                                  # ≤ 50 loc
    my ($g,$file_path) = @_;

    my $tmp  = __fifo_fa_tmpfifo($file_path);
    my $mode = 0666 & ~( umask );

    my $ok = try { _with_root( sub { mkfifo($tmp,$mode) } ) }
             catch { return error "mkfifo($tmp) failed: $_" };
    return error "mkfifo returned false" unless $ok;

    my ($fh,$e) = __fifo_fa_open_handle($tmp);
    if ($e){ unlink $tmp; return error $e }

    my $ino = __fifo_get_inode($tmp)
        or (unlink $tmp, return error "stat($tmp) failed after mkfifo");

    $g->{fh}{config}{$ino} = $fh;

    unless (__fifo_fa_watch($g,$tmp,$ino)){
        close $fh;
        delete $g->{fh}{config}{$ino};
        unlink $tmp;
        return error "Failed to watch temp FIFO [$tmp]";
    }

    unless (rename $tmp,$file_path){
        my $err = $!;
        __fifo_fifo_rm($g,$tmp,$ino);         # AI_GOOD – rollback
        return error "rename($tmp → $file_path) failed: $err";
    }

    if (my $rec=_rec($g,$ino)){ $rec->{path}=$file_path }
    else { carp "CRITICAL: Missing record for inode $ino after rename" }
    return 1;
}

#######################
#  fifo_rm (small)    #
#######################
sub __fifo_fifo_rm {                                    # AI_GOOD
    my ($g,$hint_path,$ino) = @_;
    return unless defined $ino;
    my $rec = delete $g->{monitor}{$ino} or return;

    if (my $fh = delete $g->{fh}{config}{$ino}) {
        close $fh or carp "close() failed for FIFO inode $ino: $!";
    }
    $rec->{watcher}->cancel if $rec->{watcher};

    my $curr = __fifo_get_inode($rec->{path});
    if (-p $rec->{path} && defined $curr && $curr==$ino) {
        unlink $rec->{path} or carp "unlink($rec->{path}) failed: $!";
    }
}

#####################################
#  fifo_access_and_cycle – wrapper  #
#####################################
sub __fifo_fifo_access_and_cycle {                       # AI_GOOD
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

        if (my $pids=__fifo_get_pid_open_files($path)){
            my $n=keys %$pids;
            if ($n>1){
                info "Open PIDs for [$path]: $n";
                my $dump = eval{require Data::Dump;1}
                    ? Data::Dump::dump($pids)
                    : do{ require Data::Dumper;
                          local $Data::Dumper::Indent=1;
                          Data::Dumper::Dumper($pids) };
                print "\n",$dump,"\n";
            }
        }

        if (print $fh "$path\n"){
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

sub __fifo_ie_overflow {                              # ≤ 45 loc
    my ($g,$event) = @_;
    error "inotify queue overflow – rebuilding all watches in place";

    my $inotify = __fifo_inotify_init($g);

    my %old = %{ $g->{monitor} };      # snapshot
    for my $key (keys %old){
        my $rec = $old{$key};
        my ($path,$type,$cb) = @$rec{qw/path type system_event_cb/};

        $rec->{watcher}->cancel if $rec->{watcher};

        my $re_mask = $type eq 'fifo'
            ? IN_OPEN | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF
            : IN_CLOSE_WRITE;

        my $new_w = $inotify->watch(
            $path,$re_mask,
            sub{ my $ev=shift; __fifo_inotify_event($g,$ev,$key) },
        );

        if ($new_w){ $rec->{watcher}=$new_w }
        else { error "Failed to re-watch [$path] after overflow: $!" }
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

#############################
#  get_pid_open_files       #
#############################
sub __fifo_get_pid_open_files {                        # AI_GOOD
    my ($target) = @_;
    return _with_root(sub {
        my %m;
        opendir my $dh,"/proc" or return;
        while (my $pid=readdir $dh){
            next unless $pid =~ /^\d+$/;
            next if $pid == $$;
            my $fdir="/proc/$pid/fd";
            opendir my $fdh,$fdir or next;
            while (my $fd=readdir $fdh){
                next if $fd =~ /^\.\.?$/;
                my $link=readlink("$fdir/$fd") or next;
                if ($link eq $target){ $m{$pid}=$target; last }
            }
            closedir $fdh;
        }
        closedir $dh;
        return %m ? \%m : undef;
    });
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

