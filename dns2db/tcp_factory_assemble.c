/* 
   $Id$
   
   This module will assemble tcp packets to a 
   DNS packet.
   
   HOW:
   By using a hash table, the socketpair is used as a key, and the 
   value_struct is the value.
   
   the value_struct has three members.
   data - which contains the data that suppose to be filled when all packets are received.
   size - this is the total size of the data..
   actual_size - this is how much we so far has received.

   So the basic idea is that we convert the socketpair to a specific string according to
   "ip_address_src:port_src;ip_address_dest:port" and use that as a key to the hashtable.
   
   then we check if the key exists in the hashtable
   IF it doesn't
     create a value_struct
     create a socketpair string
     create a data holder of the size specified in the first 2 bytes of the data
     insert the size (see above) to the size
     copy the data_size (input) of data into the holder
     add the data_size to actual_size.     
   IF it does
     take the data and append it to the data field in the structure.
     add the appended data size to the size in the structure.
    

   Now if the size == actual size we are done
     So we add the pointer to the IN/OUt pointer dns_data
     and return TCP_FACTORY_FULL
   IF not (that is size > actual size)
     return TCP_FACTORY_PART
   
*/
#define _GNU_SOURCE
#include <string.h>
#include <sys/types.h> /* Without this FreeBSD fails */

#include <stdio.h>
#include <stdlib.h>    /* for exit */


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h> /* iphdr and udphdr's*/
#include <netinet/ip6.h>	/* ipv6 structures */
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>	/* Tcp headers */
#include <glib.h>		/* For the hashtable */


#include "dns2db_config.h"
#include "tcp_factory_assemble.h"

static GHashTable *hashTbl=NULL;




struct value_struct
{
  uint8_t *data;
  int tot_size;
  int actual_size;
};

typedef enum {
  SRC,
  DST,
}HOST; 





void key_destroy(gpointer data)
{
  free(data);
  data = NULL;
}

void val_destroy(gpointer data)
{
  
  struct value_struct *val = (struct value_struct *) data;

  
  if(val->data != NULL)
    {
      free(val->data);
      val->data = NULL;
    }


  free(val);
  val = NULL;

}

  
static char * address_to_str(const void *addr,int af)
{
  char *ret_string;
  int str_sz=0;
  
  if(AF_INET == af)
    {
      ret_string = malloc(INET_ADDRSTRLEN);
      str_sz = INET_ADDRSTRLEN;
    }
  else if(AF_INET6 == af)
    {
      ret_string = malloc(INET6_ADDRSTRLEN);
      str_sz = INET6_ADDRSTRLEN;
    }
  
  inet_ntop(af,addr,ret_string,str_sz);
  
  return ret_string;
}


static char * create_socket_str(char *ip,uint16_t port)
{
  int str_len = strlen(ip)+SOCKET_STR_EXTRA_CHR;
  
  char *ret_str = malloc(str_len * sizeof(int));
  
  snprintf(ret_str,str_len,SOCKET_STR,ip,port);
  
  return ret_str;
  
}
  
  


/* 
   ====================
   assemble one of the socket...
   ====================

 */

static char * assemble_socket(const dns_package *pkg,HOST host)
{
  
  

  char *ip_str;
  char *socket_str;
  uint16_t port;
  struct tcphdr *tcpH = pkg->tcp_hdr;
 
  
  if(pkg->IPV == IPV4)		/* Handles IPv4 source and destination */
    {
      if(host == DST)
	{
	  ip_str= address_to_str((void *)&pkg->ipV4_hdr->ip_dst,AF_INET);
	  port = htons(tcpH->th_dport);
	}
      else
	{
	  ip_str= address_to_str((void *)&pkg->ipV4_hdr->ip_src,AF_INET);
	  port = htons(tcpH->th_sport);
	}
    }
  else if(pkg->IPV == IPV6)	/* Handles IPv6 spurce and destination */
    {
      if(host == DST)
	{
	  ip_str = address_to_str((void *)&pkg->ipV6_hdr->ip6_dst,AF_INET6);
	  port = htons(tcpH->th_dport);
	}
      else 
	{
	  ip_str = address_to_str((void *)&pkg->ipV6_hdr->ip6_src,AF_INET6);
	  port = htons(tcpH->th_sport);
	}
    }

  
  socket_str = create_socket_str(ip_str,port);
  
  free(ip_str);
  
  
  return socket_str;


}
      
  


/* 
   ====================
   Creates a key for the hashtable 
   ====================

   
   first we 

*/
static char * create_pair_str(const dns_package *pkg)
{
  char *socketPairStr= NULL;
  char *LHS_socket=NULL;
  char *RHS_socket=NULL;
  int socketP_str_len=0;
  LHS_socket = assemble_socket(pkg,DST);
  RHS_socket = assemble_socket(pkg,SRC);
  
  socketP_str_len = strlen(LHS_socket) + strlen(RHS_socket) + SOCKET_PAIR_STR_EXTRA_CHAR;
  
  socketPairStr= malloc(socketP_str_len * sizeof(char));
  
  snprintf(socketPairStr,socketP_str_len,SOCKET_PAIR_STR,LHS_socket,RHS_socket);
  
  free(LHS_socket);
  free(RHS_socket);
  
  

    
  return socketPairStr;
  
 
}
  

char *get_socket_pair(const dns_package *pkg)
{
  
  return create_pair_str(pkg);
}
  

void TCP_factory_init()
{

  hashTbl = g_hash_table_new_full(g_str_hash,g_str_equal,
				  key_destroy,val_destroy);
}

/*
  ====================
  The buffer
  ====================
  
  The principle is to add imported data to the exsting data,
  until the actual_size = tot_size

  The offset is equal to the actual_size. It points to where the new 
  data is to be placed.
  


 */
static int add_to_buffer(struct value_struct *val,const uint8_t *data,int data_len)
{
  int ret = TCP_FACTORY_ERROR;

  if(val->tot_size >= (val->actual_size+data_len))
    {
      memcpy(val->data,data,data_len);
      val->actual_size += data_len;
      
      if(val->actual_size == val->tot_size)
	{

	  ret = TCP_FACTORY_FULL;
	}
      else if ( val->tot_size < val->actual_size)
	{
	  ret = TCP_FACTORY_PART;
	}
    }
  return ret;
}  
  
       
/*
  ====================
  check_Socket_exists
  ====================
  
  This is where we check if the socket pair exists in the
  hashtable.

  if it does, take out the value and return it
  if it doesnt, return NULL
  
*/

  
static struct value_struct * check_Socket_exists(char *socketPair)
{
  struct value_struct *ret_value = NULL;
  gpointer lookupVal = NULL;

  assert(socketPair != NULL); /* Socket Pair cannot be NULL */
  
  lookupVal=g_hash_table_lookup(hashTbl,socketPair);
  
  

  if(lookupVal != NULL)
    {
      ret_value = (struct value_struct *) lookupVal;
      
    }

  return ret_value;
}   

/* 
   ====================
   create_value
   ====================
   
   Creates a value struct and inserts the total data size
   This will be freed when the hashtable uses remove.


 */

static struct value_struct *create_value(int tot_data_size)
{
  struct value_struct *val=NULL;
        
  val = malloc(sizeof(struct value_struct));
  val->actual_size =0;
  val->data = NULL;
  //assert(tot_data_size < 0 && val == NULL);
  val->tot_size =tot_data_size;
  
  val->data = malloc(tot_data_size);

  return val;
      

}

/* 
   ====================
   tcp_factory_new_packet
   ====================
   Creates a new value packet.
   and adds it to the hashtable, without 
   inserting any data to the
 */

int tcp_factory_new_packet(const char *key_str,int tot_size)
{
  struct value_struct *val = create_value(tot_size);
  int ret = TCP_FACTORY_ERROR;
  char *key_cpy=NULL;
  
  if(key_str != NULL && val != NULL)
    {
      key_cpy = strndup(key_str,strlen(key_str));
      g_hash_table_insert(hashTbl,(gpointer)key_cpy,val);
      ret = TCP_FACTORY_PART;
    }

  return ret;
}
       

/*
  ====================
  tcp_factory_add_data
  ====================
  
  add the new data. This is where we could 
  get back a value_struct if it's full.
  
  

 */

int tcp_factory_add_data(char *key_str,uint8_t *data,
			 int data_size,
			 uint8_t **dns_data)
{
  int ret = TCP_FACTORY_ERROR;
  struct value_struct *val = check_Socket_exists(key_str);
  
  assert(val != NULL);
  
  ret = add_to_buffer(val,data,data_size);
  
  if(ret == TCP_FACTORY_FULL)
    {
      *dns_data = malloc(val->tot_size);
      memcpy(*dns_data,val->data,val->tot_size);
      g_hash_table_remove(hashTbl,key_str);
    }
  
  return ret;
}
      
  
    


int tcp_factory_assemble(const dns_package *pkg,
			 int data_size,
			 uint8_t *Data,
			 int tot_data_size,
			 uint8_t **dns_data)
{
  struct value_struct *val;
  int ret = TCP_FACTORY_ERROR;
  char *socket_pair = create_pair_str(pkg);
  
  
  assert(socket_pair != NULL);	
  
  
  val = check_Socket_exists(socket_pair);
  
  if(val == NULL)		
    {
      
      val = create_value(tot_data_size);
      ret = add_to_buffer(val,Data,data_size);
      
      if(ret == TCP_FACTORY_FULL)
	{
	  *dns_data = val->data;
	  free(val);		
	}
      else if(ret == TCP_FACTORY_PART) 
	{
	  g_hash_table_insert(hashTbl,socket_pair,val);
	}
    }
  else
    {
      ret = add_to_buffer(val,Data,data_size);
      
      printf("Found parts!\n");
      
      if(ret == TCP_FACTORY_FULL)
	{
	  printf("Part full: %d %d\n",val->tot_size,tot_data_size);
	  *dns_data = val->data;
	  g_hash_table_remove(hashTbl,socket_pair); /* This 
						       should remove/free 
						       key and val */
	}
    }
  
  return ret;
}





/* 
   ====================
   tcp_factory_check_existens
   ====================

   This basically checks of the existens of
   a value based on a key..
   it returns 1 if found and 0 if not..
 */

int tcp_factory_check_existens(char *key)
{
  int retVal = 0;
  gpointer lookupVal = NULL;
  
  lookupVal=g_hash_table_lookup(hashTbl,key);
  
  if(lookupVal != NULL)
    retVal = 1;
  
  return retVal;
}
    

