/*
  $Id: ram2disk.c,v 1.1 2007/04/11 15:02:42 calle Exp $
*/
#include "config.h"
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>



#include "ram2disk.h"


int cp_ram2disk(const char *temp,const char *perm,char **errMsg)
{
  int temp_des,perm_des,bytes;
  int ret = RAM2DISK_ERROR;
  char line[RAM2DISK_LINE_BUFFER];
  
  if((temp_des = open(temp, O_RDONLY)) != -1)
    {
      
      if((perm_des = open(perm, O_WRONLY | O_CREAT)) != -1) 
	{
	  /* 
	     opened both files, now copy...
	  */
	  
	  while((bytes = read(temp_des, line, RAM2DISK_LINE_BUFFER)) > 0)
	    write(perm_des, line, bytes);
	  
	  /*
	    remove the temp file which is located in the ramdisk
	  */
	  if(unlink(temp) == 0 )
	    {
	      ret = RAM2DISK_OK;
	    }
	  else
	    {
	      *errMsg = strndup(RAM2DISK_UNLINK_FAILED,
				strlen(RAM2DISK_UNLINK_FAILED));
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
	  *errMsg = strndup(RAM2DISK_PERM_FAILED,strlen(RAM2DISK_PERM_FAILED));
	  close(temp_des);
	}


      

    }
  else
    {
      perror("Open temp:");
      *errMsg = strndup(RAM2DISK_TEMP_FAILED,strlen(RAM2DISK_TEMP_FAILED));
    }
      
	
      
  return ret;



}
      
	  
/*	
  int main(int argc, char *argv[])
  {
  char *errMsg;
  
  if(cp_ram2disk("dnslog.db","SHIT",&errMsg) == -1)
  {
  printf("did not work: %s\n", errMsg);
  }
  else
  {
  printf("worked!\n");
  }
  return 1;
  }
*/    
