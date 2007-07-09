/*
  $Id: e_filter.c,v 1.6 2007/07/06 13:59:17 calle Exp $

  Description:
  The purpose of this file, is to be able
  to create filters for e1 and e2.
  It is only possible to make regexp for e1 on qnames.
  and e2 on src address..

  e1_filter_compile - will return a function pointer in wich 
  it be used by libDNSLog
  
  e2_filter_compile - will return a function pointer to which
  can be used by libDNSLog

  That means that e1 will be taking out the 2nd level tld.
  and e2 will be based on /24 network.

*/


#include "dns2db_config.h"
#define _GNU_SOURCE
#include <string.h>

/*
  For inet_aton
*/
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/*
  For regexp
*/
#include <sys/types.h>
#include <regex.h>
/*
  Calloc,dns_message
*/
#include <stdlib.h>
#include "DNSLog.h"
#include "e_filter.h"


static regex_t *e1_preg=NULL;
static regex_t *e2_preg=NULL;

char *e1_filter(const dns_message *m,void *arg)
{
  char *ret=NULL;
  char *theQname =(char *) m->qname;
  int size =0;



  size_t nmatch=1; // Planning on one hit...:)
  regmatch_t *pmatch=calloc(nmatch,sizeof(regmatch_t));
  

  
  //Compile reg exp..

    
  //Match...
  if(regexec(e1_preg,theQname,nmatch,pmatch,0) == 0)
    {
      //Get substring..FIX ME WITH strdup instead..
      
      
      size = strlen(&theQname[pmatch[0].rm_so])+1;

      ret = malloc(size*sizeof(char));
      
      strncpy(ret,&theQname[pmatch[0].rm_so],size);
      
      
      
      
    }

    
  free(pmatch);
  return ret;
}



char *e2_filter(const dns_message *m,void *arg)
{
  char *ret=NULL;
  char *theQname;
  int size =0;

  if(m->inet_af == AF_INET)
    {
      theQname = malloc(INET_ADDRSTRLEN);
      inet_ntop(AF_INET,&m->ipv4,theQname,INET_ADDRSTRLEN);
    }
  else if(m->inet_af == AF_INET6)    
    {
      theQname = malloc(INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6,&m->ipv6,theQname,INET6_ADDRSTRLEN);
    }
  else
    {
      return NULL;
    }
	



  size_t nmatch=1; // Planning on one hit...:)
  regmatch_t *pmatch=calloc(nmatch,sizeof(regmatch_t));
  

  
  //Compile reg exp..

    
  //Match...
  if(regexec(e2_preg,theQname,nmatch,pmatch,0) == 0)
    {
      //Get substring..FIX ME WITH strdup instead..
      
      
      size = strlen(&theQname[pmatch[0].rm_so])+1;
      ret = malloc(size*sizeof(char));
      
      strncpy(ret,&theQname[pmatch[0].rm_so],size);
      
      
      
      
    }

    
  free(pmatch);
  return ret;
}

  
  
char *NET_filter(const dns_message *m,void *arg)
{
  int cnt;
  struct in_addr mask;
  struct in_addr masked_addr;
  struct in6_addr masked6_addr;
  char *buf=NULL;
  

  if(m->inet_af == AF_INET)	/* ipv4 mask... */
    {
      inet_pton(AF_INET,"255.255.255.0",&mask);	/* Get a masked network in byte order */
      masked_addr.s_addr = m->ipv4.s_addr & mask.s_addr; /* and the address with the mask */
      buf = malloc(INET_ADDRSTRLEN); /* New string */
      inet_ntop(AF_INET,&masked_addr,buf,INET_ADDRSTRLEN); /* get the ascii representation */
    }
  if(m->inet_af == AF_INET6)
    {
      /* Use the first 64 bits(network), and skip the HW address 
	 First we set the masked6_addr to 0x00 for all bits
	 Then we copy the first 64 bits of m->ipv6.....
	 and then inet_ntop...
      */
      //bzero(&masked6_addr.S6_addr,16); /* 16 bytes = 128 bits */
      bzero(&masked6_addr.s6_addr,16); /* 16 bytes = 128 bits */
      memcpy(&masked6_addr.s6_addr,m->ipv6.s6_addr,8); /* Copy the first 8 bytes */
      
      
      buf=malloc(INET6_ADDRSTRLEN);      
      inet_ntop(AF_INET6,&masked6_addr,buf,INET6_ADDRSTRLEN);
    }
	
  

  return buf;
}
      



/*
  =======================
  E1 Function to
  compile regexp, if called with NULL it will compile
  tld_reg_exp ([^\\.]+\\.[a-zA-Z]+$)
  =======================
*/

int e1_filter_compile(char *in_reg_exp,char **errorBuf)
{
  char tld_reg_exp[] = "[^\\.]+\\.[0-9a-zA-Z]+\\.$";
  char *reg_exp = in_reg_exp;
  int ret = E_FILTER_INTERNAL_ERROR;

  if(in_reg_exp == NULL)
    {
      reg_exp = tld_reg_exp;
    }


  /*
    Allocate mem for regexp
    Do not forget to free!
  */
  if((e1_preg = malloc(sizeof(regex_t))) == NULL)
    {
      *errorBuf = strndup(E_FILTER_MEM_ALLOC_ERR_STR,strlen(E_FILTER_MEM_ALLOC_ERR_STR));
      return E_FILTER_MEM_ALLOC_ERR;
    }



  if(regcomp(e1_preg,reg_exp,REG_EXTENDED | REG_ICASE)!=0)
    {
      *errorBuf = strndup(E_FILTER_REGEXP_COMP_ERROR_STR,strlen(E_FILTER_REGEXP_COMP_ERROR_STR));
      ret = E_FILTER_REGEXP_COMP_ERROR;
    }
  else
    {
      ret = E_FILTER_OK;
    }
  return ret;
}



void *e1_filter_function(char **errBuf)
{
  void *ret=NULL;
  
  if(e1_preg == NULL)
    {
      *errBuf = strndup(E_FILTER_NO_REGEXP_STR,strlen(E_FILTER_NO_REGEXP_STR));
    }
  else
    {
      ret = e1_filter;
    }
  
  return ret;
}



/*
  =======================
  E2 Function to
  compile regexp, if called with NULL it will compile
  tld_reg_exp ([^\\.]+\\.[a-zA-Z]+$)
  =======================
*/

int e2_filter_compile(char *in_reg_exp,char **errorBuf)
{
  int ret = E_FILTER_INTERNAL_ERROR;
  

  if(in_reg_exp == NULL)
    {
      return E_FILTER_USE_DEFAULT;
    }


  /*
    Allocate mem for regexp
    Do not forget to free!
  */
  if((e2_preg = malloc(sizeof(regex_t))) == NULL)
    {
      *errorBuf = strndup(E_FILTER_MEM_ALLOC_ERR_STR,strlen(E_FILTER_MEM_ALLOC_ERR_STR));
      return E_FILTER_MEM_ALLOC_ERR;
    }

  if(regcomp(e2_preg,in_reg_exp,REG_EXTENDED | REG_ICASE)!=0)
    {
      *errorBuf = strndup(E_FILTER_REGEXP_COMP_ERROR_STR,strlen(E_FILTER_REGEXP_COMP_ERROR_STR));
      ret = E_FILTER_REGEXP_COMP_ERROR;
    }
  else
    {
      ret = E_FILTER_OK;
    }
  return ret;
}






void *e2_filter_function(char **errBuf)
{
  void *ret=NULL;
  
  if(e2_preg == NULL)
    {
      ret = (void *) NET_filter;
    }
  else
    {

      
      ret = (void *)e2_filter;
    }
  
  return ret;
}


void e_filter_free(void)
{
  if(e1_preg != NULL)
    {
      free(e1_preg);
    }
  
  if(e2_preg != NULL)
    {
      free(e2_preg);
    }
}
