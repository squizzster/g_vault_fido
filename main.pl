#!/usr/bin/env perl
use strict;
use warnings;
use AnyEvent;
use FindBin;
use lib $FindBin::Bin;     # look next to this script
use Fifo;
use Data::Dump qw(dump);

#--------------------------------------------------------------------------#
# GLOBAL STATE – passed everywhere by reference
#--------------------------------------------------------------------------#
our $g = {
    fh   => { config  => {} },
    dir  => { monitor => {} },
};

my $f = Fifo::get_pid_open_files("/var/log/httpd/ssl_error_log");
print "\n";
print dump $f;
print "\n";
# Path to monitor
my $fifo = '/tmp/test.fifo';

# Kick-off: create FIFO, attach watcher
Fifo::fifo_add( $g, $fifo ) or die "Failed to start FIFO watcher. \n";

print <<"MSG";
PID $$ is watching $fifo
Try:   echo hi > $fifo
Press Ctrl-C to stop.
MSG

# Enter event loop (single-threaded)
AnyEvent->condvar->recv;

