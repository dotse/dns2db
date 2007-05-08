/*
  $Id: e_filter.c,v 1.5 2007/05/07 07:14:51 calle Exp $

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
  char *theQname = inet_ntoa(m->client_ipv4_addr);
  int size =0;



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

  struct in_addr mask;
  struct in_addr masked_addr;
  char *buf = NULL;
  char *temp=NULL;

  
  inet_aton("255.255.255.0",&mask);

  masked_addr.s_addr = m->client_ipv4_addr.s_addr & mask.s_addr;
  temp = inet_ntoa(masked_addr);
  
  if(temp != NULL)
    {

      buf = strndup(temp,strlen(temp));
      //size = strlen(temp)+1;
      //buf = malloc( size * sizeof(char));
      
      //strncpy(buf,temp,size);
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
