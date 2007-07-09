/*
  $Id: read_pcap.c,v 1.10 2007/07/06 13:59:17 calle Exp $

*/
#include "dns2db_config.h"
#define _GNU_SOURCE
#include <string.h>

#include <stdlib.h>
//#include <arpa/inet.h>
#include <pcap.h>
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
#include <netinet/udp.h> 
/*

Lets see if we can get ldns in this...

*/


#include "read_pcap.h"
 /* for portability, use config later*/
//#define strndup(str,len) strdup(str)

#ifdef __linux__
#define uh_dport dest
#define uh_sport source
#endif


//extern dns_message *handle_dns(const char *buf, int len);
static unsigned short port53;

typedef int (handle_datalink) (dns_package *m,const u_char * pkt, int len);


/*
  Objectification!
  Saves neccessary information for later use
*/
typedef struct
{
  pcap_t *pcap_obj;
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
int handle_udp(dns_package *m,const struct udphdr *udp, int len)
{
  char *buf[len];
  /*
    Allocating space for udp header.
    and insert memory to the udp header
  */
  struct udphdr *u_hdr = malloc(sizeof(struct udphdr));
  
  u_hdr=memcpy(u_hdr,udp,sizeof(struct udphdr));
  m->udp_hdr = u_hdr;
  
  


  /* I wonder if it takes care of this in ldns?? */
  if (port53 != udp->uh_dport && port53 != udp->uh_sport)
    return READ_PCAP_WRONG_PORT;
  
  
  /* 
     remove the udp header and store rest in buffer.
  */
     
  memcpy(buf, udp + 1, len - sizeof(*udp));

  
  
  return handle_dns(m,(uint8_t *)buf,len - sizeof(*udp));
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

static void test_ipv6_hdr(struct ip6_hdr *ip6)
{

  struct in6_addr *src =(struct in6_addr *) ip6->ip6_src.s6_addr;
    //ip6->ip6_src;
  char buf[INET6_ADDRSTRLEN];
  
  bzero(buf,INET6_ADDRSTRLEN);
  
  inet_ntop(AF_INET6,src,buf,INET6_ADDRSTRLEN+1);

  printf("%s \n",buf);
  
}
    
    
  



#ifdef ETHERTYPE_IPV6
int
handle_ipv6(dns_package *pkg,const struct ip6_hdr * ip6, int len)
{
  int rc;
  int nxt_proto_hdr = ip6->ip6_nxt;
  int offset = sizeof(*ip6);
  struct ip6_hdr *ip_hdr = malloc(offset);
  char buf[len]; 		/* Should probably use uint_8 instead of char */
  bzero(buf,len);

  
  ip_hdr =memcpy(ip_hdr,ip6,sizeof(struct ip6_hdr));

  
  pkg->ipV6_hdr = ip_hdr;
  
/*   test_ipv6_hdr(ip_hdr);	 */

  /* Well Actually, if the next header is something other
   than UDP we just send back some error of unknown proto..
   
  */

  /* if(IPPROTO_UDP != nxt_proto_hdr) */
  /*     return READ_PCAP_IP_UNKOWN_PROTO; */
  /*   if(IPPROTO_FRAGMENT != nxt_proto_hdr) */
  /*     return READ_PCAP_IP_FRAGMENT; */
  
  if(IPPROTO_UDP == nxt_proto_hdr)
    {
      /* Copy the rest of the content of the packet to buf */
      memcpy(buf, (void *) ip6 + offset, len - offset);
      
      /* Call handle udp with the buffer and remove the header length from the length */
      pkg->IPV = IPV6;
      rc = handle_udp(pkg,(struct udphdr *)buf,len-offset);
      return rc;
    }
  
  
  
  printf("IPV6 message found \n");

  return READ_PCAP_IP_UNKOWN_PROTO;
}
#endif



/*
  ======================
  Handle ipv4 packet!
  ======================
*/


int handle_ipv4(dns_package *m,const struct ip * ip, int len)
{

  struct ip *i_hdr = malloc(sizeof(struct ip));
  char *buf[len];
  

  /*
    allocating memory for ip header
     and inserts that to dns_package for
     later use.
  */
  i_hdr =memcpy(i_hdr,ip,sizeof(struct ip));
  m->ipV4_hdr = i_hdr;

  int offset = ip->ip_hl << 2;



    /*
      NOT IMPLEMTED!!
      ip_message_callback(ip);
    */
  if (IPPROTO_UDP != ip->ip_p)
    return READ_PCAP_IP_UNKOWN_PROTO;
    /* sigh, punt on IP fragments */
  if (ntohs(ip->ip_off) & IP_OFFMASK)
    return READ_PCAP_IP_FRAGMENT;


  /*
    take away the ip header and insert
    that into buf, this buffer is used for
    udp header and dns packet info.
  */
  memcpy(buf, (void *) ip + offset, len - offset);
  
  
  m->IPV = IPV4;
  return handle_udp(m,(struct udphdr *) buf, len - offset);

}

/*
  ======================
  Handles Ethernet packet!
  ======================
*/

int 
handle_ether(dns_package *m,const u_char *pkt, int len)
{
  unsigned short etype;
  char buf[len];
  struct ether_header *e_hdr = malloc(sizeof(struct ether_header));

  
  e_hdr = memcpy(e_hdr,pkt,sizeof(struct ether_header));
  etype = ntohs(e_hdr->ether_type);
    
  if (len < ETHER_HDR_LEN)
    return READ_PCAP_ETHER_HEADER_LEN_PROBLEM;
  pkt += ETHER_HDR_LEN;
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
    memcpy(buf, pkt, len); /* copy the remaingin packet into buf and send off*/
    m->e_hdr = e_hdr;
    return handle_ipv4(m,(struct ip *) buf, len);

  }


  if (ETHERTYPE_IPV6 == etype) {
    memcpy(buf, pkt, len);
    return handle_ipv6(m,(struct ip6_hdr *) buf, len);
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
handle_pcap(read_pcap_struct *obj,dns_package *m, const u_char * pkt)
{
  if (m->pcap_hdr->caplen < ETHER_HDR_LEN)
    return READ_PCAP_PCAP_HEADER_LEN_PROBLEM;

  return obj->link(m,pkt,m->pcap_hdr->caplen);;
}


/*
  =======================
  Implemting bpf filter
  =======================
*/

int read_pcap_bpf_filter(void *pobj,char *bpf,char **errBuf)
{
  int ret;
  struct bpf_program filter;
  memset(&filter, '\0', sizeof(filter));
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

  
  ret = pcap_compile(obj->pcap_obj, &filter, bpf, 1, 0);
  if (ret < 0) 
    {

      *errBuf=strndup(READ_PCAP_BPF_COMPILE_STR,
		      strlen(READ_PCAP_BPF_COMPILE_STR));
      pcap_geterr(obj->pcap_obj);
      return READ_PCAP_BPF_COMPILE;
    }
  ret= pcap_setfilter(obj->pcap_obj, &filter);
  
  if(ret < 0)
    {
      *errBuf=strndup(READ_PCAP_BPF_SETFILTER_STR,
		      strlen(READ_PCAP_BPF_SETFILTER_STR));
      pcap_geterr(obj->pcap_obj);
      
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

  read_pcap_struct *obj;
  struct stat sb;
  char pcap_errBuf[PCAP_ERRBUF_SIZE];
  pcap_t *new_pcap;
  
  if (0 != stat(file_name, &sb))
    {
      *errBuf = strndup(READ_PCAP_NO_FILE_STR,
			strlen(READ_PCAP_NO_FILE_STR));
      return READ_PCAP_NO_FILE;
    }
  
  if((new_pcap = pcap_open_offline(file_name, pcap_errBuf)) == NULL)
    {
      *errBuf = strndup(pcap_errBuf,strlen(pcap_errBuf));
      return READ_PCAP_FAILED_OFFLINE;
    }

  
  
  /*
    BPF Program...
  */


  
  /*
    If everyting worked until this,
    its time to allocate memory for the obj struct.
  */
  obj = malloc(sizeof(read_pcap_struct));
  obj->pcap_obj = new_pcap;
  
  obj->QRA=A;
  // we create some static port..
  port53 = htons(53);
  
  switch (pcap_datalink(new_pcap)) 
    {
    case DLT_EN10MB:
      obj->link = handle_ether;
      break;
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
  
  *reader_obj = (void *) obj;
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
  

  if(m->e_hdr != NULL)
    {
      free(m->e_hdr);
      m->e_hdr = NULL;
    }
  if(m->ip_hdr.ip4 != NULL)
    {
      free(m->ip_hdr.ip4);
      m->ip_hdr.ip4 = NULL;
    }
  if(m->udp_hdr != NULL)
    {
      free(m->udp_hdr);
      m->udp_hdr = NULL;
    }
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
  int res,ret=0;
  dns_package *m=malloc(sizeof(dns_package));
  int cont_read=READ_PCAP_CONT;
  int o =0;
  int fails =0;
  
  read_pcap_struct *obj= (read_pcap_struct *) read_obj;
  
  init_dns_packet(m);
  
  while((res = pcap_next_ex( obj->pcap_obj, &header, &pkt_data)) >= 0 && cont_read == READ_PCAP_CONT)
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

      m->pcap_hdr= malloc(sizeof(struct pcap_pkthdr));
      m->pcap_hdr=memcpy(m->pcap_hdr,header,sizeof(struct pcap_pkthdr));
      ret=handle_pcap(obj,m,pkt_data);      
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
      else
	{
	  /*
	    Something went wrong,
	    its either a ipv6 or not a 
	    dns packet.
	    
	    No error message please ;)
	  */
	  fails++;
	  //printf("ERROR %d\n",ret);
	}
      free_dns(m);
    }
  free(m);
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
      if(obj->pcap_obj != NULL)
	{
	  free(obj->pcap_obj);
	  obj->pcap_obj = NULL;
	}
      
      if(obj->link != NULL)
	{
	  obj->link = NULL;
	}
      free(obj);
    }
  
}
  
	
  


  
