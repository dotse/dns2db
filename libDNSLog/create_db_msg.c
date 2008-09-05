/* 
   $Id: create_db_msg.c,v 1.6 2007/07/06 13:59:42 calle Exp $
   
   
*/

#define _GNU_SOURCE
#include "config.h"
#include "DNSLog.h"
#include "DNSLog_Int.h"
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

static void initialize_message(dns_message *msg)
{
  msg->ts.tv_sec = 0;
  msg->ts.tv_usec = 0;
  
  //msg->client_ipv4_addr.s_addr = 0;
  msg->msg_id = 0;
  msg->src_port = 0;
  msg->qtype = 0;
  msg->qclass = 0;
  msg->msglen = 0;
  bzero(msg->qname,MAX_QNAME_SZ);
  msg->opcode =0;
  msg->rcode=0;
  msg->malformed=0;
  msg->qr=FALSE;
  msg->rd=FALSE;
  msg->edns.found = FALSE;
  msg->edns.DO= FALSE;
  msg->edns.version = 2;
}


/*
  Creates new object
*/

int DNSLog_create_msg(void **obj,char **errorMsg)
{
  int ret=DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = malloc(sizeof(dns_message));
  
  if(msg != NULL)
    {
      ret = DNS_LOG_OK;
      initialize_message(msg);
      *obj = msg;
      
    }
  else
    {
      *errorMsg = strndup(DNS_LOG_FAILED_MEMORY_ALLOC_STR,
			  strlen(DNS_LOG_FAILED_MEMORY_ALLOC_STR));
      ret = DNS_LOG_FAILED_MEMORY_ALLOC;
    }
  
  return ret;
}


/*
  under construction
  Need to add more stuff as soon as i've done the
  inserts..
*/


int DNSLog_destroy_msg(void *obj)
{
  int ret=DNS_LOG_INTERNAL_ERROR;
  dns_message *msg= (dns_message *) obj;
  
  if(msg != NULL)
    {
      free(msg);
      ret = DNS_LOG_OK;
    }
  return ret;
}
      
  
/*
  ======================
  DNSLog_set_timeval Function
  sets the timeval in dns_message struct..
*/

int DNSLog_set_timeval(void *obj, struct timeval *tv,char **errorMsg)  
{
  
  int ret = DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = (dns_message *) obj;

    
  if(tv != NULL)
    {
      memcpy(&msg->ts,tv,sizeof(struct timeval));
      ret =DNS_LOG_OK;
    }
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return ret;
}
  
  
  
  
/*
  DNSLog_get_timeval
  Returns the timeval structure..
  shallow copy.
*/


struct timeval *DNSLog_get_timeval(void *obj)
{
  struct timeval *ret= NULL;
  dns_message *msg = (dns_message *) obj;
  
  if(msg != NULL)
    {
      
      ret = &msg->ts;
    }
  return ret;
}
    

/*
  ====================
  DNSLog_set_addr functions
  Sets the client_ipv4_addr
  in dns_message
*/


int DNSLog_set_addr(void *obj,uint32_t addr,char **errorMsg)
{
  int ret = DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = (dns_message *) obj;
  
  if(msg != NULL)
    {
      
      memcpy(&msg->ipv4,(void *) &addr,sizeof(struct in_addr));
      ret = DNS_LOG_OK;
      msg->inet_af = AF_INET;
    }
  else
    {
      
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return ret;
}

/* 
   DNSLog_set_client_addr is a v2 of DNSLog_set_addr
   with support of ipv6
   the address should be the raw 
 */
int DNSLog_set_client_addr(void *obj,const void *addr,int af,char **errorMsg)
{
  int ret = DNS_LOG_INTERNAL_ERROR;

  

  dns_message *msg = (dns_message *) obj;

  /* Check that obj is not null */
  if(obj != NULL)
    {
  
      /* IF AF_INET then ipv4 */
      if(af == AF_INET)
	{
	  
	  memcpy(&msg->ipv4.s_addr,addr,4);	/* Copy 4 bytes (32-bits) */
	  msg->inet_af = af;
	  ret = DNS_LOG_OK;
	}
      /* IPv6 */
      else if(af == AF_INET6)
	{
	  memcpy(msg->ipv6.s6_addr,addr,16); /* Copy 16 bytes (128-bits) */
	  msg->inet_af = af;
	  ret = DNS_LOG_OK;
	}
      else
	{
	  ret =DNS_LOG_MSG_WRONG_AF;
	  *errorMsg = strndup(DNS_LOG_MSG_WRONG_AF_STR,strlen(DNS_LOG_MSG_WRONG_AF_STR));
	}
    }
      
  return ret;
      
}

/*
  DNSLog_get_addr
  returns a struct in_addr from the object
*/

/* struct in_addr *DNSLog_get_addr(void *obj) */
/* { */
/*   struct in_addr *ret_addr=NULL; */
/*   dns_message *msg = (dns_message *) obj; */
  
/*   if(msg != NULL) */
/*     { */
/*       ret_addr = &msg->ipv4; */
/*     } */
/*   return ret_addr; */
/* } */


/*
  ==============
  DNSLog_set_msgID
  in/out: obj
  out: isSet
  
  sets the message id on the object.
*/

int DNSLog_set_msgID(void *obj,uint16_t id,char **errorMsg)
{
  int ret = DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = (dns_message *) obj;
  
  if(msg != NULL)
    {
      
      msg->msg_id = id;
      ret = DNS_LOG_OK;
    }
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return ret;
}
      

/*
    DNSLog_get_msgID
    returns msg id
    if error returns 0...
*/
uint16_t DNSLog_get_msgID(void *obj,char **errorMsg)
{
  
  uint16_t ret=0;
  dns_message *msg = (dns_message *) obj;
  
  if(msg != NULL)
    ret = msg->msg_id;
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return ret;
}

/*
  ========================
  DNSLog_set_src_port
  
*/
     
int DNSLog_set_src_port(void *obj,uint16_t port,char **errorMsg)
{
  dns_message *msg = (dns_message *) obj;
  int ret = DNS_LOG_INTERNAL_ERROR;
  
  
  if(msg != NULL)
    {
      ret = DNS_LOG_OK;
      msg->src_port = port;
    }
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return ret;
}
      


uint16_t DNSLog_get_src_port(void *obj, char **errorMsg)
{
  uint16_t ret_port = 0;
  
  dns_message *msg = (dns_message *) obj;
  
  if(msg != NULL)
    ret_port = msg->src_port;
  else
    {
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
    
  return ret_port;
}
    
/*
  =======================
  DNSLog_set_qtype
  
*/

int DNSLog_set_qtype(void *obj,uint16_t query_type, char **errorMsg)
{
  int ret = DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = (dns_message *) obj;
  
  if(msg != NULL)
    {
      ret = DNS_LOG_OK;
      msg->qtype = query_type;
    }
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return ret;
}


uint16_t DNSLog_get_qtype(void *obj,char **errorMsg)
{
  uint16_t ret=999;
  dns_message *msg = (dns_message *) obj;
  
  if(msg != NULL)
    {
      
      ret = msg->qtype;
    }
    else
    {
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return ret;
}  

/*
  =======================
  DNSLog_set_qclass
*/

uint16_t DNSLog_set_qclass(void *obj, uint16_t query_class, 
		      char **errorMsg)
{
  
  int ret = DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = (dns_message *) obj;
  
  if(msg != NULL)
    {
      msg->qclass = query_class;
      ret = DNS_LOG_OK;
    }
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return ret;
}



uint16_t DNSLog_get_qclass(void *obj,char **errorMsg)
{
  uint16_t ret = 999;
  dns_message *msg = (dns_message *) obj;
  
  if( msg != NULL)
    ret = msg->qclass;
  else
    {
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }

  
  return ret;
}

/*
  =======================
  message Length
*/
      
int DNSLog_set_msglen(void *obj,uint16_t msg_len,char **errorMsg)
{
    dns_message *msg = (dns_message *) obj;
    int ret = DNS_LOG_INTERNAL_ERROR;
    
    if(msg != NULL)
      {
	ret = DNS_LOG_OK;
	msg->msglen = msg_len;
      }
    else
      {
	ret = DNS_LOG_NULL_POINTER;
	*errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			    strlen(DNS_LOG_NULL_POINTER_STR));
      }
    return ret;
}
    
  

uint16_t DNSLog_get_msglen(void *obj,char **errorMsg)
{
  uint16_t ret_val=0;
  dns_message *msg = (dns_message *) obj;
  
  if(msg != NULL)
    {
      ret_val = msg->msglen;
    }
  else
    {
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return ret_val;
}

/*
  =======================
  QNAME
  DNSLog_set_qname
  
*/

static void convert_to_lower(char *toConvert)
{
  int len = strlen(toConvert);
  int i;

  for(i=0;i < len; i++)
    {
      
      /*
	Its a alphabetic letter
      */
      if(isalpha(toConvert[i]) == 1)
	{
	  toConvert[i] = tolower(toConvert[i]);
	}
    }
}



int DNSLog_set_qname(void *obj, const char *query_name, char **errorMsg)
{
  int ret = DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = (dns_message *) obj;
  
  
  
  if(msg != NULL)
    {
      
      memcpy(msg->qname,query_name,strlen(query_name)+1);
      convert_to_lower(msg->qname);
      ret = DNS_LOG_OK;
    }
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  return ret;
}
  



char *DNSLog_get_qname(void *obj,char **errorMsg)
{
  char *ret_qname = NULL;
  dns_message *msg = (dns_message *) obj;
  
  if(msg != NULL)
    {
      ret_qname = msg->qname;
      
    }
  else
    {
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return ret_qname;
}
     

/*
  =======================
  WE SKIP THE TLD! 
  Do not think its neccessary..
  
  set opcode and get opcopde
*/


int DNSLog_set_opcode(void *obj,uint8_t opcode,char **errorMsg)
{
  int ret = DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = (dns_message *) obj;
  
  if(msg != NULL)
    {
      
      msg->opcode = opcode;
      ret = DNS_LOG_OK;
      
    }
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
      
  
  return ret;
}
  

  
uint8_t DNSLog_get_opcode(void *obj,char **errorMsg)
{
  dns_message *msg = (dns_message *) obj;
  uint8_t ret_val=10;
  
  if(msg != NULL)
    {
      ret_val = msg->opcode;
    }
  else
    {
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  return ret_val;
}



      
/*
  =======================
  set rcode and get rcode

*/
int DNSLog_set_rcode(void *obj,uint8_t rcode,char **errorMsg)
{
  int ret = DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = (dns_message *) obj;
  
  if(msg != NULL)
    {
      
      msg->rcode = rcode;
      ret = DNS_LOG_OK;
      
    }
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
      
  
  return ret;
}
  

  
uint8_t DNSLog_get_rcode(void *obj,char **errorMsg)
{
  dns_message *msg = (dns_message *) obj;
  uint8_t ret_val=10;
  
  if(msg != NULL)
    {
      ret_val = msg->rcode;
    }
  else
    {
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return ret_val;
}


/*
  =======================
  SKIPPING MALFORMED
  
  is query
*/

int DNSLog_set_isQuery(void *obj,DNSLOG_BOOL isQ,char **errorMsg)
{
  int ret = DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = (dns_message *) obj;

  if( msg != NULL)
    {
	  msg->qr = isQ;
	  ret = DNS_LOG_OK;
      
    }
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  
  return ret;
}

DNSLOG_BOOL DNSLog_get_isQuery(void *obj,char **errorMsg)
{
  DNSLOG_BOOL isQ=FALSE;
  dns_message *msg = (dns_message *) obj;


  if(msg != NULL)
    {
      isQ = msg->qr;
    }
  else
    {
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return isQ;
}
  
     
/*
  =======================
  Recursive desired
*/

int DNSLog_set_isRecursive(void *obj,DNSLOG_BOOL isRec,char **errorMsg)
{
  int ret = DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = (dns_message *) obj;

  if( msg != NULL)
    {
	  msg->rd = isRec;
	  ret = DNS_LOG_OK;
      
    }
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  
  return ret;
}

DNSLOG_BOOL DNSLog_get_Recursive(void *obj,char **errorMsg)
{
  DNSLOG_BOOL isQ=FALSE;
  dns_message *msg = (dns_message *) obj;


  if(msg != NULL)
    {
      isQ = msg->qr;
    }
  else
    {
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return isQ;
}

/*
  =======================
  Hmmm..
  
*/


int DNSLog_set_edns_opt_RR(void *obj,DNSLOG_BOOL isFound,char **errorMsg)
{
  int ret = DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = (dns_message *) obj;

  if( msg != NULL)
    {
	  msg->edns.found = isFound;
	  ret = DNS_LOG_OK;
      
    }
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  
  return ret;
}


DNSLOG_BOOL DNSLog_get_edns_opt_RR(void *obj,char **errorMsg)
{
  DNSLOG_BOOL isFound=FALSE;
  dns_message *msg = (dns_message *) obj;


  if(msg != NULL)
    {
      isFound = msg->edns.found;
    }
  else
    {
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return isFound;
}

/*
  =======================
  DO bit -field for edns..
*/

int DNSLog_set_edns_DO(void *obj, DNSLOG_BOOL isSet, char **errorMsg)
{
  
  int ret = DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = (dns_message *) obj;

  if( msg != NULL)
    {
	  msg->edns.DO = isSet;
	  ret = DNS_LOG_OK;
      
    }
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  
  return ret;
}


DNSLOG_BOOL DNSLog_get_edns_DO(void *obj,char **errorMsg)
{
  DNSLOG_BOOL isFound=FALSE;
  dns_message *msg = (dns_message *) obj;


  if(msg != NULL)
    {
      isFound = msg->edns.DO;
    }
  else
    {
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return isFound;
}


/*
  =======================
  edns- version...
*/

int DNSLog_set_edns_version(void *obj, uint8_t version, char **errorMsg)
{
  
  int ret = DNS_LOG_INTERNAL_ERROR;
  dns_message *msg = (dns_message *) obj;

  if( msg != NULL)
    {
	  msg->edns.version = version;
	  ret = DNS_LOG_OK;
      
    }
  else
    {
      ret = DNS_LOG_NULL_POINTER;
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  
  return ret;
}


uint8_t DNSLog_get_edns_version(void *obj,char **errorMsg)
{
  uint8_t version= 100;
  dns_message *msg = (dns_message *) obj;


  if(msg != NULL)
    {
      version = msg->edns.version;
    }
  else
    {
      *errorMsg = strndup(DNS_LOG_NULL_POINTER_STR,
			  strlen(DNS_LOG_NULL_POINTER_STR));
    }
  
  return version;
}
