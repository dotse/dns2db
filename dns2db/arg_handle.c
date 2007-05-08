
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>    /* for exit */
#include <getopt.h>
#include "arg_handle.h"

//#include "dns2db.h" /* for portability, use config later*/
#include "dns2db_config.h" /* for portability, use config later*/

void read_pcap_usage(void)
{
  printf("{{{{{{{{{{{{}}}}}}}}}}}}\n");
  printf(" Using version %s \n",PACKAGE_STRING);
  printf(" %s [opts] <tcpdump files> \n",PACKAGE_NAME);
  printf(" Bugs reports can be sent to %s\n",PACKAGE_BUGREPORT);
  printf("}}}}}}}}}}}}{{{{{{{{{{{{");
  printf("\n");
  printf(" [opts]\n");
  printf(" --type (-t)\t[sqlite]\n");
  printf(" --help (-h)\t this\n");
  printf(" --version (-v)\tShows current version\n");
  printf(" --queries_only (-q)\tOnly process queries\n");
  printf(" --replies_only (-r)\tOnly process replies\n");
  printf(" --database (-d) <file>\tUse <file> as database\n");
  printf(" --query_table (-e) <table_name>\tUse <table_name> for queries\n");
  printf(" --reply_table (-f) <table_name>\tUse <table_name> for replies\n");
  printf(" --qname_regexp (-n) <regexp>\tUse <regexp> on qname and insert into a new column\n");
  printf(" --src_regexp (-s) <regexp>\tUse <regexp> on src address and insert into a new column\n");
  printf(" --bpf (-b)\tUse berkley packet filter on each packet\n");
  printf(" --db_overwrite (-o)\toverwrite if current db file exists\n");

}


/*
  Check options

  §1. en modul som processar argumenten..

    1.1 Vi har ett argument för bara frågor. (-q)
    1.2 Vi har ett argument för bara Svar. (-r)
        Om ingen av dom ovanstående är specificerade kommer
	både query och reply användas..

    1.3 Vi har ett argument för databas namn (-t)
    1.4 Vi har ett argument för tabellnamn för frågor (--query-table)
	Default kommer vara Q
    1.5 Vi har ett argument för tabellnamn för svar (--reply-table)
	Default kommer vara R
    1.6 Vi har ett argument för vilken slags databastyp (--type)
	Där default är sqlite (och bara implemnterat i denna version)
    1.7 Ett argument med regexp som tar på qname,
	Då kommer det också finnas ett extra fält i databasen
	(--qname-regexp) (default?? i så fall som tidigare?)	
    1.8 Ett argument med regexp som tar på src,
	Då kommer det också finnas ett extra fält i databasen
	(--host-regexp)(default?? i så fall som tidigare?)
    1.9 Ett argument för berkely packet fileter 
	(--bpf_program)
    
    2.0 Ett argument med tids intervall (Implementeras senare)
    2.1 Ett argument om överskrivning på databasen dvs om den existerar.
	(--overwrite)
    2.1 Slutligen är argumenten för pcap filerna. +


+ Innebär att den är obligatorisk
*/




arg_struct *check_options(int argc,char** argv)
{
  arg_struct *arg_sr = malloc(sizeof(arg_struct));
  int c;
  int option_index = 0;
  char *file=NULL;



  arg_sr->overwrite = 0;
  arg_sr->type = NULL;
  arg_sr->qo = 0;
  arg_sr->ro = 0;
  arg_sr->database = NULL;
  arg_sr->q_table = NULL;
  arg_sr->r_table = NULL;
  arg_sr->q_regexp = NULL;
  arg_sr->src_regexp = NULL;
  arg_sr->bpf = NULL;
  arg_sr->pcap_files = NULL;
  arg_sr->nr_files =0;
  
  struct option long_options[] = {
    {"type",1,0,'t'},
    {"help",0,0,'h'},
    {"version",0,0,'v'},
    {"queries_only",0,0,'q'},    
    {"replies_only",0,0,'r'},    
    {"database",1,0,'d'},    
    {"query_table",1,0,'e'},    
    {"reply_table",1,0,'f'},    
    {"qname_regexp",1,0,'n'},
    {"src_regexp",1,0,'s'},
    {"db_overwrite",0,0,'o'},
    {"bpf",1,0,'b'},
    {0, 0, 0, 0}
  }; 
  
  while((c=getopt_long (argc, argv, "borvqht:ld:1e:1f:1:n:1s:1b:1",
			long_options, &option_index)) != -1)
    {
      switch(c)
	{
	case 't':
	  printf("Using db type %s (NOT IMPLEMENTED)\n",optarg);
	  arg_sr->type = strndup(optarg,strlen(optarg));	  
	  break;
	  
	case 'h':
	  read_pcap_usage();	  
	  exit(0);
	  break;
	  
	case 'v':
	  printf("You are currently running on version %s\n",PACKAGE_VERSION);
	  exit(0);
	  break;

	case 'q':
	  arg_sr->qo = 1;
	  break;
	  
	case 'r':
	  arg_sr->ro = 1;
	  break;
	  
	case 'e':
	  printf("Using query table %s\n",optarg);
	  arg_sr->q_table=strndup(optarg,strlen(optarg));
	  break;
	  
	case 'f':
	  printf("Using reply table %s\n",optarg);
	  arg_sr->r_table=strndup(optarg,strlen(optarg));
	  break;
	  

	case 's':
	  printf("Using source regexp %s\n",optarg);
	  arg_sr->src_regexp=strndup(optarg,strlen(optarg));
	  break;
	  
	case 'n':
	  printf("Using qname regexp %s\n",optarg);
	  arg_sr->q_regexp=strndup(optarg,strlen(optarg));
	  break;
	  
	case 'd':
	  printf("Using database %s\n",optarg);
	  arg_sr->database = strndup(optarg,strlen(optarg));
	  break;

	case 'o':
	  printf("Overwrite option is set\n");
	  arg_sr->overwrite = 1;
	  break;
	  
	case 'b':
	  arg_sr->bpf = strndup(optarg,strlen(optarg));
	  break;


	case '?':
	  read_pcap_usage();
	  printf("Got something else %s\n",optarg);
	  break;

	  
	default:
	  read_pcap_usage();
	  printf ("?? getopt returned character code 0%o ??\n", c);
	  break;
	}
    }

  if ( optind < argc) {
    //printf ("Using pcap files: ");
    
    if( (arg_sr->pcap_files = calloc(argc-optind, sizeof(char *))) == NULL)
      exit(EXIT_FAILURE);


     while (optind < argc)
       {
	 file =strndup(argv[optind],strlen(argv[optind]));;
	 (arg_sr->pcap_files)[arg_sr->nr_files++] = file;
	 optind++;

       }
     //printf ("\n");
     
   }
   else
     {
       read_pcap_usage();
       printf("Need to specify what pcap files to use\n");
       exit(EXIT_SUCCESS);
     }
   
   return arg_sr;
	
}
