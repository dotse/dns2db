#!/usr/bin/perl

use POSIX;
use Sys::Syslog;
use Sys::Syslog qw(:DEFAULT setlogsock);  # default set, plus setlogsock()

$user = $ENV{'USER'};

setlogsock('unix');
openlog('dns2db','','user');


use POSIX;
use Sys::Syslog;
#use POSIX qw(setsid);

$conffile = "/etc/dns2db.conf";

######### read config file

open(CONFIG,$conffile) or die "error reading config file $conffile exiting";
while (<CONFIG>) {
    chomp;
    next if /^\s*\#/;
    next unless /=/;
    my ($key, $variable) = split(/=/,$_,2);
    $variable =~ s/(\$(\w+))/$config{$2}/g;
    $config{$key} = $variable;
}


$pidfile  = $config{'pidfile'};
$logfile  = "/dev/null";

##### start daemon


&daemonize();

##### catch signals

my $keep_going = 1;
$SIG{HUP}  = sub { print("Caught SIGHUP:   exiting gracefully\n"); $keep_going = 0; };
$SIG{INT}  = sub { print("Caught SIGINT:   exiting gracefully\n"); $keep_going = 0; };
$SIG{QUIT} = sub { print("Caught SIGQUIT:  exiting gracefully\n"); $keep_going = 0; };
$SIG{TERM} = sub { print("Caught SIGTERM:  exiting gracefully\n"); $keep_going = 0; };



########## start collection

$interval  = $config{'interval'};
$interface = $config{'interface'};
$filter    = $config{'filter'};
$filter   =~ s/^\"(.*)\"$/$1/;

$workdir   = $config{'workdir'};
$workdir  =~ s/^\"(.*)\"$/$1/;

$server    = $config{'server'};
$server   =~ s/^\"(.*)\"$/$1/;

$destdir   = $config{'destdir'};
$destdir  =~ s/^\"(.*)\"$/$1/;

$user 	   = $config{'user'};

$index 	   = $config{'index'};
$index    =~ s/^\"(.*)\"$/$1/;

$compress  = $config{'compresspcap'};

$template  = $config{'template'};

$stime = floor(time()/$interval) * $interval + $interval;


syslog LOG_INFO,"Starting dns2db daemon (pid:".$$.")\n";
syslog LOG_INFO,"  workdir: ".$config{'workdir'}."\n";
syslog LOG_INFO," template: ".$config{'template'}."\n";
syslog LOG_INFO,"  destdir: ".$config{'destdir'}."\n";
syslog LOG_INFO," comppcap: ".$compress."\n";
syslog LOG_INFO,"    index: ".$index."\n";

local *TCPDUMP;
$tdpid = 0;
if ($config{'bsdpromischack'} eq "YES")
{
    $tcpdumpcmd="$config{'tcpdump'} -i $interface port 100 2>/dev/null";
    $tdpid = open(TCPDUMP, "$tcpdumpcmd |") || die "can't fork: $!";
    syslog LOG_INFO,"Keeping the interface ($interface) in promisc mode by letting tcpdump ($tdpid) listen on port 100 \n";
}


$tracesplitcmd = $config{'tracesplit'}." pcapint:$interface -s $stime -i $interval -f \"$filter\" pcapfile:$workdir/$server";
$tspid = open(TSPLIT, "$tracesplitcmd |") || die "can't fork: $!";
syslog LOG_INFO,"Starting tracesplit (pid:$tspid)\n";


########## infinite loop

chdir $workdir;

#`rm -f *.gz`;

while($keep_going == 1)
{
   @gzfiles = ();
   @usfiles = `find $workdir -type f ! -name *.core`;
   foreach (@usfiles)
   {
        $file = $_;
        $file =~ s/\n//g;
        # only use gz files
        if ($file =~ /^.*gz$/)
        {
            push(@gzfiles,$file);
        }
   }
  
   # sort&shift in order to never use the latest file as 
   # tracesplit might still be caching data for it
   @files = reverse sort(@gzfiles);
   shift(@files);
   
   foreach (@files)
   {
        $file = $_;
        $tid = $file;
        $tid =~ s/^.*[^0-9]([0-9]*)[.]gz.*$/$1/;
        $age = time()- $tid - $interval - 2;
        if (-s $file == 0)
        {
            `rm $file`
        }
        else
        {
            if (($age gt 0)&&($file =~ /^.*gz$/))
            {
                # generate file names based on the current time 
                ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime($tid);
                $year+=1900;
                $dir = sprintf("%d%02d%02d", $year,($mon+1),$mday);
                $name = $server."-".sprintf("%d%02d%02d%02d%02d", $year,($mon+1),$mday,$hour,$min);
                $pcap= $name.".pcap";
                $db = $name.".db";
                syslog LOG_INFO,"Processing $name\n";
                
                # rename the current pcap file
                `mv $file $pcap`;

                
                # run tracedns and sqlite
                $tracednscmd ="tracedns -p 0 pcapfile:$pcap | dns2sqlite -o -t $template -d $server -f $workdir";
		`$tracednscmd`;

                # Rename outputfile with correct time 
                `mv $dir/* $dir/$db`;	

                # create sqlite indexes
		`sqlite3 $dir/$db "${index}"`;
#		`sqlite3 $dir/$db "create index ix_src_addr on q (src_addr);"`;
#		`sqlite3 $dir/$db "create index domain on q (rr_lvl2dom,rr_lvl1dom);"`;
#		`sqlite3 $dir/$db "create index ix_rr_type on q (rr_type);"`;

                # create the destination directory
		`mkdir -p $destdir/$dir`;

                # move db files to destdir
		`mv $dir/$db $destdir/$dir/$db`;

                # recompress the pcap file with max compression and move it to destdir

                if ($config{'keeppcap'} eq "YES")
                {
	            if ($compress eq "YES")
		    {
                    	`zcat $pcap | gzip -9 > $destdir/$dir/$pcap.gz`;
                    }
                    else
		    {
                    	`zcat $pcap > $destdir/$dir/$pcap`;
                    }
                }
                `rm $pcap`;
		`rm -rf $dir`;
				

                # change the destination files owner 
		`chown -R $user $destdir/$dir`;
		`chmod -R 755 $destdir/$dir/`;
                
                # move coredumps - ignore errors
		`mv *.core $destdir/$dir/ 2>/dev/null`;
            }
        }
   }
   sleep(5);
}


########## exit cleanup

syslog 'info',"Shutting down DNS2db ...\n";
syslog LOG_INFO,"Stopping tracesplit\n";
kill( - SIGABRT, $tspid);
close TSPLIT;

if ($tdpid ne 0)
{
    syslog LOG_INFO,"Stopping tcpdump ($tdpid)\n";
    kill( - SIGABRT, $tdpid);
    close TCPDUMP;
}

syslog LOG_INFO,"removing pidfile\n";
unlink($pidfile);

syslog LOG_INFO,"bye bye\n";
closelog;
exit;

##########  functions


sub daemonize {

    if (-e $pidfile)
    {
       open (PFILE, $pidfile);
       $pidfromfile = <PFILE>;
 
       if (kill( 0, $pidfromfile))
       {            
            if ($ARGV[0] eq 'stop')
            {
	        syslog 'info',"Stopping daemon pid: $pidfromfile\n";
                while (kill( 0, $pidfromfile))
                {
                    kill( - SIGQUIT, $pidfromfile);
                    sleep(1);
                }
            }
            else
            {
                syslog LOG_INFO,"Pid file $pidfile exist and the program ($pidfromfile) is running ! exiting ...\n"; 
            }
            exit;
       }
       else 
       {
            unlink($pidfile);
       }
    }
    
    if ($ARGV[0] eq 'stop')
    {
        syslog 'info',"Cannot stop dns2db.pl as it's not running\n";
        exit;
    }

    chdir '/'                 or die "Can't chdir to /: $!";
    defined(my $pid = fork)   or die "Can't fork: $!";
    exit if $pid;
    setsid                    or die "Can't start a new session: $!";
    umask 0;

    open FILE, ">$pidfile" or die "unable to open pidfile : $pidfile $!";
    print FILE $$;
    close FILE;


    open STDIN, '/dev/null'   or die "Can't read /dev/null: $!";
    open STDOUT, ">>$logfile" or die "Can't write to $logfile: $!";
    open STDERR, ">>$logfile" or die "Can't write to $logfile: $!";
}




