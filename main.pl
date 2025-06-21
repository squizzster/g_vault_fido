#!/usr/bin/env perl
#######  [v1.0 loader]  ########
use v5.14; # May 2011
use strict;use warnings;use utf8;binmode(STDIN,':encoding(UTF-8)');binmode(STDOUT,':encoding(UTF-8)');binmode(STDERR,':encoding(UTF-8)');$|=1;my$g;use FindBin qw($RealBin $RealScript);BEGIN{$g->{dir}={exe=>"$RealBin/$RealScript",path=>$RealBin,sock=>"$RealBin/sock",lib=>"$RealBin/lib",conf=>"$RealBin/conf"};-r$g->{dir}{exe}or die"FATAL:$g->{dir}{exe} not found\n";my($u,$gid)=(stat $g->{dir}{exe})[4,5];defined$u or die"FATAL:stat failed\n";$g->{user}={uid=>$u,gid=>$gid}}; BEGIN{($g->{user}{uid}||$g->{user}{gid})&& do{use lib"$g->{dir}{path}/lib";require set_uuid;set_uuid::set_uuid($g->{user}{uid},$g->{user}{gid},1)||die"Failed to drop privileges: $!"}}; use lib $g->{dir}{path}.'/lib';my%seen;my@f=grep{my$b=$_;$b=~s{^.*/}{};!$seen{$b}++}(glob("$g->{dir}{lib}/*.pm"),glob("common_lib/*.pm"));my$e='';eval{for(@f){next unless -f$_&&/\.pm$/;open(my$h,'<',$_)or($e.="Can't open $_: $!\n",next);my$p=0;for(1..10){last unless defined(my$l=<$h>);$p=1,last if$l=~/^\s*package\s+\S+;/}close$h;if($p){(my$m=$_)=~s{^.*/}{};$m=~s/\.pm$//;$m=~s{/}{::}g;eval"require $m" or $e.="Error using $m: $@\n"}else{do$_ or $e.="Error in file $_:[".($@||"Make sure it evaluates to 'true'")."]\n"}}};$e.=$@ if$@;$e and print STDERR"\nCompilation failed:\n$e"and exit 1;undef $e;undef @f;undef %seen;
package main;
#######  [loader done]  ########

# log
use Log::Any::Adapter;
Log::Any::Adapter->set('Stderr');
#

# other
use AnyEvent;
use Data::Dump qw(dump);
use Time::HiRes qw(time);
#

print dump $g;
print "\n";
my $target = "/var/log/httpd/ssl_error_log";

my $t1 = time();
my $f1 = pid::pids_holding_file($target);
my $elapsed1 = time() - $t1;
print dump $f1;
print "\n";
printf "get_pid_open_files      took: %.6f seconds\n", $elapsed1;

#print dump $f2;
print "\n";

ev_signal::start ( $g );

Fifo::fifo_add   ( $g, '/tmp/test.fifo'           ) or die "Failed to start FIFO watcher. \n";
Fifo::fifo_add   ( $g, '/etc/my.cnf.d/client.cnf' ) or die "Failed to start FIFO watcher. \n";
Fifo::fifo_add   ( $g, 'hello'                    ) or die "Failed to start FIFO watcher. \n";

ev_socket::add(
                   $g,
                   path      => '/tmp/woofwoof.sock',
                   mode      => 0644,
                   backlog   => 20,
                   abstract  => 1,           # 0 or 1 (abstract namespace)
                   rbuf_max  => 8 * 1024,    # read buffer (bytes)
                   wbuf_max  => 8 * 1024,    # write buffer (bytes)
                   timeout   => 0.5,         # connection timeout (seconds, can be 0)
);

print "\n[START] [$$].\n";
AnyEvent->condvar->recv;

END {
    # Cleanup code here,
    ev_signal::stop($g); ## example of good clean-up! (start / stop);
    print "Cleaning up before exit...\n\n\n\n\n\n\n\n\n\n\n\n\n";
    print ( dump $g);
    print "\nClean exit. (well it will be at some point).\n";
}
