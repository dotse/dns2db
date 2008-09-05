/*
  $Id: dns2db.h,v 1.8 2007/07/06 13:59:17 calle Exp $
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

  typedef enum {IPV4=4,IPV6=6,}IP_VERSION;



struct _dns_package
{
  ldns_pkt *pkt;

  union PROTO_HDR{
    struct udphdr *udp;  
    struct tcphdr *tcp;
  } _proto_hdr;
  #define udp_hdr _proto_hdr.udp
  #define tcp_hdr _proto_hdr.tcp
  

  union IP_HDR{
    struct ip *ip4;
    struct ip6_hdr *ip6;
  } ip_hdr;
  
  IP_VERSION IPV;
  
  struct ether_header *e_hdr;
  struct pcap_pkthdr *pcap_hdr;
};

#define ipV4_hdr ip_hdr.ip4
#define ipV6_hdr ip_hdr.ip6

#endif

#ifndef ETHER_HDR_LEN

#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_LEN 2
#define ETHER_HDR_LEN (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)

#define DEFAULT_DB "dnslog.db"




#endif
