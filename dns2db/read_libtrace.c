
/*
  $Id: read_pcap.c,v 1.10 2007/07/06 13:59:17 calle Exp $

*/
#include "dns2db_config.h"
#define _GNU_SOURCE
#include <string.h>

#include <stdlib.h>
//#include <arpa/inet.h>
#include <pcap.h>
#include <libtrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netinet/in.h> /* Provides IP protocol info
			   e.h IPPROTO_UDP definition
			*/
#include <sys/socket.h>
#include <netinet/ip6.h>	/* Provides ip6 structures */
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/if_ether.h>



#include <netinet/in_systm.h> /* iphdr and udphdr's*/
#include <netinet/ip.h>
#include <netinet/tcp.h>	/* Tcp headers */
#include <netinet/udp.h> 	/* Udp headers */
/*

Lets see if we can get ldns in this...

*/


#include "read_pcap.h"
#include "tcp_factory_assemble.h"

static unsigned short port53;

typedef int (handle_datalink) (dns_package *m,libtrace_packet_t *pkt, int len);


/*
  Objectification!
  Saves neccessary information for later use
*/
typedef struct
{
  libtrace_t *trace_obj;
  handle_datalink *link;
  pkg_capture QRA;
} read_pcap_struct;


int handle_dns(dns_package *m,uint8_t *pkg,int len)
{
  ldns_pkt *pkt=NULL;
  ldns_status status;

  status = ldns_wire2pkt(&pkt,(uint8_t *)pkg,len);
  
  if(status != LDNS_STATUS_OK)
    {
      if(pkt != NULL)
	{
	  free(pkt);
	}
	    
      return READ_PCAP_DNS_PKT_ERROR;
    }
  
  m->pkt = pkt;
  
  return READ_PCAP_OK;
}
  
  

/*
  ======================
  Handle udp Packet!
  
  To use ldns..
  
  ======================
*/
int handle_udp(dns_package *m,libtrace_packet_t *pkt, int len)
{
  int ret = READ_PCAP_DNS_PKT_ERROR;
  void *payload=NULL;
  libtrace_udp_t *u_hdr = trace_get_udp(pkt);
  uint32_t remaining;
  uint16_t header_len=htons(u_hdr->len);
  int hdr_size = len - sizeof(*u_hdr);
  
  
  m->udp_hdr = (struct udphdr *)u_hdr; /* Using 'struct udphdr' for compatibility
					  reasons */
  
  
  /* I wonder if it takes care of this in ldns?? */
  if (port53 != u_hdr->dest && port53 != u_hdr->source)
    return READ_PCAP_WRONG_PORT;
  
  /*
    remove the udp header and store rest in buffer. 
  */
  payload = trace_get_payload_from_udp(u_hdr,&remaining);
  

  
  return handle_dns(m,payload,remaining);
  
}
 


/* 
   =======================
   TCP- assemble
   =======================
                    len
   <-------------------------------------->

       tcp_len 	       	  DNS_len   
   <------------>    <-------------------->
   ----------------------------------------
   |  tcp header |   |    DNS packet      |
   ----------------------------------------
       	       	  <-->		 
 		   ^- dns_len_tot
		    		 
	
   Some good things to know
   DNS_len = len - tcp_len -2 ,  This is how much data we get from the packet
   That actually belongs to DNS packet
   
   offset = tcp_len + 2, The offset from the beginning to the start 
   of DNS packet.
   
   tcp_header = We get from the header.

   dns_len_tot = Are two bytes that tells us how exactly how big the 
   DNS packet are (reassembled).

   we create two new buffers:
   struct *t_hdr  = size of tcp header, that is not the tcp_len due to that
   we will skip the option fields. So its merly 20 bytes.

   buf - which is the buffer that holds the DNS packet, it needs to be DNS_len big
   
   Abstract:

   create a socket pair
   
   IF the SPAIR exists
     Take the data add the data to the existing until
     we have dns_len_tot..in the buffer which is identified by
     the SPAIR
     IF total_data_size == dns_len_tot
       We can proceed with the existing data, and process the DNS packet
     ELSE
       Do nothing
       
   Else
     IF dns_len_tot = DNS_len
       We can proceed with the existing data..
     Else
       create a new SPAIR as key and data as value.
     ENDIF
   ENDIF
   
   
   
	
 */

   
static int handle_tcp(dns_package *pkg, libtrace_packet_t *pkt, int len)
{
  int exists=0;
  uint32_t remaining;
  int tcp_factory_rv=TCP_FACTORY_ERROR;
  int ret=READ_PCAP_TCP_ERROR;
  uint8_t *size_cnt;

  libtrace_tcp_t *tcp = trace_get_tcp(pkt);

  int tcp_len = tcp->doff*4;	/* Get the header legth */
  
  uint32_t DNS_len=len - tcp_len; /* Remove the tcp header from the
				     length, the rest should belong to
				     the payload*/
  
  uint8_t *tcp_raw = trace_get_payload_from_tcp(tcp,&remaining);


  uint8_t *dns_data=NULL;
  char *socketPair = NULL;
  int dns_len_tot=0;
  
  


  

/* 
   We are only intrested when psh and ack is set 
   And of course there are different ways of testing this
   if the mashine is RFC 793 compliant..
   This should always work for read_libtrace
 */
  if( (tcp->psh && tcp->ack) && DNS_len > 0)	
    {				/* all other packets is of now use */
      
      pkg->tcp_hdr = (struct tcphdr *) tcp;	/* Ok we saved the
						   header, in the
						   orignal format*/

      
      
      socketPair = get_socket_pair(pkg);
      //printf("Socket pair: %s\n",socketPair);


      exists = tcp_factory_check_existens(socketPair);


      if(DNS_len <= READ_PCAP_DNS_HDR_SIZE && exists != 1)
	{
	  /* So we conclude that this is a new message
	     with zero bytes...Just the legth..
	  */
	  memcpy(&dns_len_tot,tcp_raw,1);
	  dns_len_tot << 2;
	  memcpy(&dns_len_tot,tcp_raw+1,1);

	  
	  
	  /* Get the first length bytes, 
	     it only matters if the key doesnt exists
	     
	  */
	  tcp_factory_rv= tcp_factory_new_packet(socketPair,dns_len_tot);
	  
	}
      else if(DNS_len > READ_PCAP_DNS_HDR_SIZE && exists == 1)
	{
	  /* It exists and has new data 
	     insert the new data to hash,
	     we dont need total size, its already set.
	  */
	  tcp_factory_rv=tcp_factory_add_data(socketPair,
					      tcp_raw,
					      DNS_len,
					      &dns_data);
	  

	}
      else if(DNS_len > READ_PCAP_DNS_HDR_SIZE && exists != 1)
	{
	  /* It does not exists and has data... 
	     get the length , and insert the data
	  */
	  memcpy(&dns_len_tot,tcp_raw,1);
	  dns_len_tot << 2;
	  memcpy(&dns_len_tot,tcp_raw+1,1);

	  DNS_len -= 2;		/*  Remove the first 2 bytes */
	  

	  tcp_factory_new_packet(socketPair,dns_len_tot);
	  /* Create a new value... */
				 
	  tcp_factory_rv=tcp_factory_add_data(socketPair,
					      tcp_raw+2,
					      DNS_len,
					      &dns_data);
	  /* Add the data */
	  
	}
      else if(DNS_len <= READ_PCAP_DNS_HDR_SIZE && exists == 1)
	{
	  /*
	    In this case the data exists,
	    so we assume that this is some kind of
	    data that needs to be reassambled.
	    insert....
	   */
	  tcp_factory_rv=tcp_factory_add_data(socketPair,
					      tcp_raw,
					      DNS_len,
					      &dns_data);
	  
	  
	}
      
      free(socketPair);		/* No need for it anymore */
      

      if(tcp_factory_rv == TCP_FACTORY_FULL)
	{
	  ret = handle_dns(pkg,dns_data,DNS_len);
	  //printf("Compare: %s\n",(memcmp(buf,dns_data,dns_len_tot) == 0) ? "Same" : "Not same");
	  //printf("We got FULL data it is: %s size: %d tot_size: %d \n", 
	  //(ret == READ_PCAP_OK) ? "OK" : "ERROR",
	  //DNS_len,dns_len_tot		
	  //);
	  
	  //free(dns_data);	/* No need */
	  
	}
      else if(tcp_factory_rv == TCP_FACTORY_PART)
	{
	  /* We got fragment of the packet... 
	     its ok, but should not be processed... 
	  */
	  ret = READ_PCAP_NOT_PROCESS;
	}
      else
	{
	  printf("ERROR!!!\n");
	}
	
		
	  
    }
  return ret;
}
  
/*
  ======================
  Handle ipv6 packet!
  ======================
  

  
    We need to extract the ipv6 address structure
    which is which is defined in rfc2292 (see also 2553)...
    The dns_package needs to have a union which can
    either fit that structure or the ipv4 structure..
    
  

*/



#ifdef ETHERTYPE_IPV6
int
handle_ipv6(dns_package *pkg,libtrace_packet_t *pkt, int len)
{
  int rc = READ_PCAP_IP_UNKOWN_PROTO; 
  /* if the next header is something other
   than UDP/TCP we just send back some error of unknown proto..
  */
  
  libtrace_ip6_t *ip_hdr = trace_get_ip6(pkt);
  


  int nxt_proto_hdr = ip_hdr->nxt;
  int offset = sizeof(*ip_hdr);
  
  pkg->ipV6_hdr = (struct ip6_hdr *)ip_hdr;
  

  if(IPPROTO_UDP == nxt_proto_hdr)
    {
      /* Call handle udp with the buffer and remove the header length from the length */
      pkg->IPV = IPV6;
      rc = handle_udp(pkg,pkt,len - offset);
      return rc;
    }
  else if(IPPROTO_TCP == nxt_proto_hdr)
    {

      pkg->IPV = IPV6;

      rc = handle_tcp(pkg,pkt,len-offset);
      
    }
  
  
  

  return rc;
}
#endif



/*
  ======================
  Handle ipv4 packet!
  ======================
*/


int handle_ipv4(dns_package *m,libtrace_packet_t *pkt, int len)
{
  int ret = READ_PCAP_IP_UNKOWN_PROTO;
  libtrace_ip_t *i_hdr=trace_get_ip(pkt);
  

  m->ipV4_hdr = (struct ip *) i_hdr; /* Using the original instead of libtrace */

  int offset = i_hdr->ip_hl << 2;

  
  if(IPPROTO_TCP == i_hdr->ip_p)
    {
      
      m->IPV = IPV4;      
      ret= handle_tcp(m,pkt,len-offset);
    }
  else if (ntohs(i_hdr->ip_off) & IP_OFFMASK)
    ret = READ_PCAP_IP_FRAGMENT;
  else if(IPPROTO_UDP == i_hdr->ip_p)
    {

        /*
	  take away the ip header and insert
	  that into buf, this buffer is used for
	  udp header and dns packet info.
	*/
      m->IPV = IPV4;
      ret = handle_udp(m,pkt, len-offset);
    }
  
  return ret;

}

/*
  ======================
  Handles Ethernet packet!
  ======================
*/

int 
handle_ether(dns_package *m,libtrace_packet_t *pkt, int len)
{
  unsigned short etype;
  //  char buf[len];
  struct ether_header *e_hdr = trace_get_link(pkt);
  etype = ntohs(e_hdr->ether_type);
    
  if (len < ETHER_HDR_LEN)
    return READ_PCAP_ETHER_HEADER_LEN_PROBLEM;

  len -= ETHER_HDR_LEN;
 
  /*
    VLAN - NOT IMPLEMETED YET!
    if (ETHERTYPE_8021Q == etype) {
    if (!match_vlan(pkt))
    return NULL;
    etype = ntohs(*(unsigned short *) (pkt + 2));
    pkt += 4;
    len -= 4;
    }
  */

  if (len < 0)
    return READ_PCAP_ETHER_UNSUFFICIENT_LEN;


  if (ETHERTYPE_IP == etype) {
    return handle_ipv4(m,pkt, len);

  }


  if (ETHERTYPE_IPV6 == etype) {
    return handle_ipv6(m,pkt, len);
  }

  
return READ_PCAP_UNKOWN_ETHER_TYPE;
}



  



/*
  ======================
  Handle Pcap packet!
  ======================
  Needs the read_pcap_struct to be able to use the
  link layer function...
*/

int 
handle_pcap(read_pcap_struct *obj,dns_package *m,  libtrace_packet_t *pkt)
{
  int size=trace_get_capture_length(pkt);
  if (m->pcap_hdr->caplen < ETHER_HDR_LEN)
    return READ_PCAP_PCAP_HEADER_LEN_PROBLEM;
  
  
  return obj->link(m,pkt,size);;
}


/*
  =======================
  Implemting bpf filter
  =======================
*/

int read_pcap_bpf_filter(void *pobj,char *bpf,char **errBuf)
{
  
  int ret;
  libtrace_filter_t *trace_filter;
  //memset(&filter, '\0', sizeof(filter));
  read_pcap_struct *obj= (read_pcap_struct *) pobj;


  /*
    Initial tests
  */
  if(bpf == NULL)
    {
      *errBuf = strndup(READ_PCAP_BPF_COMPILE_STR,
			strlen(READ_PCAP_BPF_COMPILE_STR));

      return READ_PCAP_BPF_COMPILE;
    }
	
  if(obj == NULL)
    {
      *errBuf = strndup(READ_PCAP_NO_READ_PCAP_STR,
			strlen(READ_PCAP_NO_READ_PCAP_STR));
      return READ_PCAP_NO_READ_PCAP;
    }

  
  trace_filter = trace_create_filter(bpf);
  

  ret = trace_config(obj->trace_obj,TRACE_OPTION_FILTER,trace_filter);



  
  if(ret)
    {
      *errBuf=strndup(READ_PCAP_BPF_SETFILTER_STR,
		      strlen(READ_PCAP_BPF_SETFILTER_STR));
      
      
      return READ_PCAP_BPF_SETFILTER;
    }
  return READ_PCAP_OK;
      
}


/*
  ======================
  Function Name: read_pcap_init
  in: file_name,bpf_program
  in/out: errBuf,reader_obj
  out: read_pcap_ok

  Description:

  arguments:
  fileName: pcap filename, the file to read from
  bpf_program: berkley packet filter string
  errBuf: In case of error this will be set, otherwise NULL
  reader_obj: used to save information about the current 
              pcap readings.

  This function will open the pcap file for reading,
  it will also compile the bpfprogram for injection.
  
  ======================
*/
int read_pcap_init(void **reader_obj,const char *file_name, char *bpf_program,char **errBuf)
{
  
  libtrace_t *trace;
  read_pcap_struct *obj;
  struct stat sb;
  char pcap_errBuf[PCAP_ERRBUF_SIZE];
  
  if((trace = trace_create(file_name)) == NULL)
    {
      *errBuf = strndup(pcap_errBuf,strlen(pcap_errBuf));
      return READ_PCAP_FAILED_OFFLINE;
    }

  
  
  /*
    BPF Program...
    NOT IMPLEMETED HERE!!
    Obsolete!!!
  */


  
  /*
    If everyting worked until this,
    its time to allocate memory for the obj struct.
  */
  obj = malloc(sizeof(read_pcap_struct));
  obj->trace_obj = trace;
  
  obj->QRA=A;

  port53 = htons(53);		/* we create some static port.. for
				   port recogition later on*/
  
  
/*   switch (trace->type) 
/*     { 
/*     case (TRACE_RT_DATA_DLT+TRACE_DLT_EN10MB): */
      obj->link = handle_ether;
      /*break;
      
      #if USE_PPP
      case DLT_PPP:
      _//datalink = handle_ppp;
      break;
      #endif
      #ifdef DLT_LOOP
      case DLT_LOOP:
      //handle_datalink = handle_loop;
      break;
      #endif
      #ifdef DLT_RAW
      case DLT_RAW:
      //handle_datalink = handle_raw;
      break;
      #endif
      case DLT_NULL:
      //handle_datalink = handle_null;
      break;
      
      default:
      *errBuf = strndup(READ_PCAP_UNSOPPORTED_LINK_STR,
      strlen(READ_PCAP_UNSOPPORTED_LINK_STR));
      return READ_PCAP_UNSOPPORTED_LINK;
      break;
      }
      */
  *reader_obj = (void *) obj;
  TCP_factory_init();
  
  return READ_PCAP_OK;
  
}    



/*
  =======================
  read_pcap_Set_QRA
  =======================
  This function sets the object
  to either use 
  Q - Queries 
  R - Replies 
  A - All 

  pkg_capture is a enumeration of either the above short..
  
*/


int read_pcap_Set_QRA(void *readp_obj,pkg_capture to_catch,char **errBuf)
{
  int ret;
  read_pcap_struct *obj= (read_pcap_struct *) readp_obj;
  if(obj != NULL)
    {
      obj->QRA = to_catch;
      ret = READ_PCAP_OK;
    }
  else
    {
      ret = READ_PCAP_NO_READ_PCAP;
      *errBuf = strndup(READ_PCAP_NO_READ_PCAP_STR,strlen(READ_PCAP_NO_READ_PCAP_STR));
    }
      
      
  return ret;
}
       

/*
  =======================
  Check_to_proceed
  =======================
  This function checks
  if the message should be used further by the callback function.
  This function uses the QRA in the reader object.
  
  
*/

static int Check_to_proceed(read_pcap_struct *obj,dns_package *msg)
{
  
  int ret = 0;
  unsigned int kind = msg->pkt->_header->_qr;
  
  /*
    Check if A is set, then we'r done
  */
  if(obj->QRA == A)
    {
      ret = 1;
    }
  // If set to question and kind is a question, then ok
  else if(obj->QRA == Q && kind == 0)
    {
      ret = 1;
    }
  //if set to reply and kind is a reply, then ok...
  else if(obj->QRA == R && kind == 1)
    {
      ret = 1;
    }
  //everything else should not be processed.
  else
    {
      ret = 0;
    }
  
  return ret;
}


void free_dns(dns_package *m)
{
  

  //  if(m->e_hdr != NULL)
  // {
  //   free(m->e_hdr);
  //  m->e_hdr = NULL;
  // }
  //if(m->ip_hdr.ip4 != NULL)	/* Should not matter if we use ipv6 or ipv4 */
  // {
  //free(m->ip_hdr.ip4);
  //m->ip_hdr.ip4 = NULL;
  // }
  //if(m->udp_hdr != NULL)	/* Same as above */
  // {
  //   free(m->udp_hdr);
  //   m->udp_hdr = NULL;
  //  }
  if(m->pkt != NULL)
    {
      ldns_pkt_free(m->pkt);
      m->pkt = NULL;
    }


}


static void init_dns_packet(dns_package *pkg)
{
  
  pkg->pkt = NULL;
  pkg->udp_hdr= NULL;
  pkg->ip_hdr.ip4 = NULL;
  pkg->ip_hdr.ip6 = NULL;
  pkg->e_hdr =NULL;
  pkg->pcap_hdr = NULL;
}
  


//=========================
/*
  Function: read_pcap_exec
  input: readObj
  output: isOk

  QRA is set to A(all) by default...
  
*/


int read_pcap_exec(void *read_obj,HMSG *message_callback, void *cb_arg)
{
  struct pcap_pkthdr *header;
  const u_char *pkt_data;
  libtrace_packet_t *packet;
  int res,ret=0;
  dns_package *m=malloc(sizeof(dns_package));
  int cont_read=READ_PCAP_CONT;
  int o =0;
  int fails =0;
  
  read_pcap_struct *obj= (read_pcap_struct *) read_obj;
  

  if(trace_start(obj->trace_obj) != 0)
    {
      ret = READ_PCAP_FAILED_OFFLINE;
      return ret;
    }

  init_dns_packet(m);
  packet = trace_create_packet();

  
  
  //while((res = pcap_next_ex( obj->pcap_obj, &header, &pkt_data)) >= 0 && cont_read == READ_PCAP_CONT)
  while(trace_read_packet(obj->trace_obj,packet)>0)
    {
      init_dns_packet(m);
      /* 
	 So we capture a package, store it....
	 Now lets unwrap it and put it into 
	 the dns_package strcucture (m)
      */
      
      
      o++;
      /*
	Storing the pcap header 
	in the dns_structure...
      */


      m->pcap_hdr = packet->header;
      ret=handle_pcap(obj,m,packet);      
      if( ret == READ_PCAP_OK) 
	{
	  
	  
	  

	  if(message_callback != NULL && Check_to_proceed(obj,m) == 1)
	    {
	      /*
		Calling the callback function with a 
		dns_package and extra argument
	      */
		
	      cont_read=message_callback(m,cb_arg);
	    }
	  
	  
	   
	}
      else if(ret == READ_PCAP_NOT_PROCESS)
	{
	  /*  Do not process its a fragment
	      ex. a tcp packet.
	   */
	}

      else
	{
	  /*
	    Something went wrong,
	    No error message please ;)
	  */
	  fails++;
	  //printf("ERROR %d\n",ret);
	}
      free_dns(m);
    }
  free(m);
  trace_destroy_packet(packet);
  printf("processed %d packets\n",o);
  printf("failed to process: %d (most commonly due to wrong format)\n",fails);
  return o;
}


/*
  =======================
  Free the object
  =======================
*/

void read_pcap_free(void *read_obj)
{
  read_pcap_struct *obj= (read_pcap_struct *) read_obj;

  if(obj != NULL)
    {
      if(obj->trace_obj != NULL)
	{
	  trace_destroy(obj->trace_obj);
	  obj->trace_obj = NULL;
	}
      
      if(obj->link != NULL)
	{
	  obj->link = NULL;
	}
      free(obj);
    }
  
}
  

	
  


  
