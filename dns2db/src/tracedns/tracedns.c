/* Complete libtrace skeleton program
 *
 * This libtrace skeleton includes everything you need for a useful libtrace
 * program, including command line parsing, dealing with bpf filters etc.
 *
 */
#include <libtrace.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "packet_handler.h"

FILE *pipeh=0;
FILE *duperr=0;

static void usage (char * argv0) {
   fprintf (stdout, "usage: %s [ --filter | -f bpfexp ]  [ --snaplen | -s snap ]\n\t\t[ --promisc | -p flag] [ --help | -h ] [ --libtrace-help | -H ] libtraceuri...\n", argv0);
}

// function that echo all output to stderr to both stderr and syslog
void echo()
{
   char str[300];
   while (fgets(str,sizeof(str),pipeh))
   {
      fprintf(duperr,"%s",str);
      syslog (LOG_ERR|LOG_USER, "%s",str);
   }
}

int main (int argc, char * argv []) {
   libtrace_t * trace;
   libtrace_packet_t * packet;
   libtrace_filter_t * filter = NULL;
   int snaplen = -1;
   int promisc = 1; // promisc < 1 = off, promisc >= 1 on.

   int pipenos[2];
   int flags;
   int stderrdup;

   // open syslog
   openlog("tracedns",LOG_PID,LOG_USER);  // open d2log

   // store a handle to the real stderr
   stderrdup = dup(2);

   // create a pipe then redirect stderr into that pipe
   pipe(pipenos);
   dup2(pipenos[1],2 /*stderr*/);

   flags = fcntl(pipenos[0], F_GETFL, 0);
   flags |= O_NONBLOCK;
   fcntl(pipenos[0], F_SETFL, flags);
   pipeh = fdopen(pipenos[0],"r");
   duperr = fdopen(stderrdup,"w");

   while (1) {
      echo();

      int option_index;
      struct option long_options [] = {
         {"filter", 1, 0, 'f'},
         {"snaplen", 1, 0, 's'},
         {"promisc", 1, 0, 'p'},
         {"help", 0, 0, 'h'},
         {"libtrace-help", 0, 0, 'H'},
         {"version", 0, 0, 'v'},
         {NULL, 0, 0, 0}
      };

      int c = getopt_long (argc, argv, "f:s:p:hHv", long_options, &option_index);

      if (c == -1)
         break;

      switch (c) {
         case 'v':
            fprintf (stdout, "%s\n", TRACEDNS_VERSION); // TRACEDNS_VERSION defined in global.h
            exit (0);
            break;
         case 'f':
            filter = trace_create_filter (optarg);
            break;
         case 's':
            snaplen = atoi (optarg);
            break;
         case 'p':
            promisc = atoi (optarg);
            break;
         case 'H':
            trace_help ();
            return 1;
         default:
            fprintf (stderr, "Unknown option: %c\n", c);
            /* FALL THRU */
         case 'h':
            usage (argv [0]);
            echo();            
            return 1;
      }
   }

   if (optind >= argc) {
      fprintf (stderr, "Missing input uri\n");
      usage (argv [0]);
      return 1;
   }

   while (optind < argc) {
      trace = trace_create (argv [optind]);
      ++optind;

      if (trace_is_err (trace)) {
         trace_perror (trace, "Opening trace file");
         echo(); 
         return 1;
      }

      if (snaplen > 0)
         if (trace_config (trace, TRACE_OPTION_SNAPLEN, &snaplen)) {
            trace_perror (trace, "ignoring: ");
         }
      if (promisc != -1) {
         if (trace_config (trace, TRACE_OPTION_PROMISC, &promisc)) {
            trace_perror (trace, "ignoring: ");
         }
      }

      if (trace_start (trace)) {
         trace_perror (trace, "Starting trace");
         trace_destroy (trace);
         echo(); 
         return 1;
      }

      packet = trace_create_packet ();

      while (trace_read_packet (trace, packet) > 0) {
	 if(!filter || (trace_apply_filter(filter,packet)>0)) {
            per_packet (packet);
            echo();
	 }
      }

      trace_destroy_packet (packet);

      if (trace_is_err (trace)) {
         trace_perror (trace, "Reading packets");
      }

      trace_destroy (trace);
   }
   echo(); 
 
   closelog();
   return 0;
}
