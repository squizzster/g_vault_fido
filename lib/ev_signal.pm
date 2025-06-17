package ev_signal;
use strict;
use warnings;
use AnyEvent;

sub start {
    my ($g) = @_;

    my @trap_signals = qw(
        HUP TRAP INT QUIT PIPE ABRT ILL BUS USR1
        SEGV USR2 ALRM TERM STKFLT STOP TSTP TTIN
        TTOU XCPU XFSZ VTALRM PWR PROF WINCH IO SYS
        CHLD CONT URG FPE
    );

    foreach my $signal (@trap_signals) {
        my $w = AE::signal $signal => sub {
            ev_signal::signal_received($g, $signal);
        };
    
        if (defined $w) {
            # success: store it
            $g->{_watcher}->{signal}->{$signal} = $w;
        }
        else {
            # failure: print an error, maybe abort... but for now I think it's OK.
            warn "✘ Failed to install watcher for $signal\n";
        }
    }
}

sub signal_received {
    my ($g, $signal) = @_;
    return if not defined $g;
    return if not defined $g->{_watcher};
    return if not defined $g->{_watcher}->{signal};
    print STDERR "I have received the [$signal] signal.\n";
    exit if $signal eq 'INT';
    return 1;
}

sub stop {
    my ($g) = @_;

    # nothing to do if we never set any watchers
    return unless $g->{_watcher}{signal}
               && ref $g->{_watcher}{signal} eq 'HASH';

    my @signames = keys %{ $g->{_watcher}{signal} };

    for my $sig (@signames) {
        delete $g->{_watcher}{signal}{$sig};
    }

    delete $g->{_watcher}{signal};
}

1;


1;

