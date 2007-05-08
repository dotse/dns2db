#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int rename(const char *temp,const char *perm)
{
  int temp_des,perm_des,bytes;
  int ret = -1;
  char line[1024];
  
  if((temp_des = open(temp, O_RDONLY)) != -1)
    {
      if((perm_des = open(perm, O_WRONLY | O_CREAT)) != -1) 
	{
	  /* 
	     opened both files, now copy...
	  */
	  
	  while((bytes = read(temp_des, line, 1024)) > 0)
	    write(perm_des, line, bytes);
	  
	  /*
	    remove the temp file which is located in the ramdisk
	  */
	  if(unlink(temp) == 0 )
	    {
	      ret = 1;
	    }
	  else
	    {
	      fprintf(stderr,"Error while removing temp");
	    }

	  /*
	    Close both filedesriptors
	  */
	  close(temp_des);
	  close(perm_des);
	}
      else
	{
	  perror("Open Permanent:");
	  close(temp_des);
	}
    }
  else
    {
      perror("Open temp:");
    }
  chmod(perm, S_IRUSR |S_IWUSR | S_IRGRP | S_IROTH );
  return ret;
}


int
main(int argc, char *argv[])
{
    pcap_t *in = NULL;
    pcap_dumper_t *out = NULL;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    struct pcap_pkthdr hdr;
    time_t this_bin;
    time_t last_bin = -1;
    time_t modulus = 300;
    const u_char *data;
    char *fmt;
    char fname[128];
    char *tmpname;


    if (4 != argc) {
        fprintf(stderr, "usage: tcpdump-split seconds strftime tempfile\n");
        exit(1);
    }
    modulus = (time_t) atoi(argv[1]);
    fmt = strdup(argv[2]);
    tmpname = strdup(argv[3]);

    in = pcap_open_offline("-", errbuf);
    if (NULL == in) {
        fprintf(stderr, "stdin: %s", errbuf);
        exit(1);
    }
    while ((data = pcap_next(in, &hdr))) {
      this_bin = hdr.ts.tv_sec - (hdr.ts.tv_sec % modulus);
        if (this_bin != last_bin) {
	  if (out)
	    {
	      pcap_dump_close(out);
	      /*
		rename tmp to permanent..
	      */
	      rename(tmpname,fname);
	      
	    }
            strftime(fname, 128, fmt, localtime(&this_bin));
            out = pcap_dump_open(in, tmpname);
            if (NULL == out) {
                perror(tmpname);
                exit(1);
            }
            last_bin = this_bin;
        }
        pcap_dump((void *)out, &hdr, data);
    }
    if (out)
      {
        pcap_dump_close(out);
	rename(tmpname,fname);
      }
    exit(0);
}

