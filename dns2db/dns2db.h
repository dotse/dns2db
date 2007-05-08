/*
  $Id: dns2db.h,v 1.6 2007/05/05 16:41:19 calle Exp $
  This file is used to give all global defintions..
  
*/





#ifndef DNS_MESSAGE
#define DNS_MESSAGE
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <ldns/ldns.h>




#define MAX_QNAME_SZ 512


typedef struct _dns_package dns_package;


struct _dns_package
{
  ldns_pkt *pkt;
  struct udphdr *udp_hdr;  
  struct ip *ip_hdr;
  struct ether_header *e_hdr;
  struct pcap_pkthdr *pcap_hdr;
};

#endif

#ifndef ETHER_HDR_LEN

#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_LEN 2
#define ETHER_HDR_LEN (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)

#define DEFAULT_DB "dnslog.db"




#endif
