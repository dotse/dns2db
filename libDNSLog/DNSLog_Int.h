/*
  $Id: DNSLog_Int.h,v 1.2 2007/07/06 13:59:42 calle Exp $
*/

#ifndef DNS_LOG_INTERNAL
#define DNS_LOG_INTERNAL
#include "DNSLog.h"

#define MAX_QNAME_SZ 512

typedef struct _dns_message dns_message;
struct _dns_message {
  struct timeval ts;
  
  struct client_ip{
    union ip_version
    {
      struct in_addr IPv4;	/* IPv4 32-bits address */
      struct in6_addr IPv6;	/* IPV6 128-bits address */
    } IPV;
    int af;
  }ip_handler;
  
  
  //struct in_addr client_ipv4_addr;
  uint16_t msg_id;
  uint16_t src_port;
  uint16_t qtype;
  uint16_t qclass;
  uint16_t msglen;
  char qname[MAX_QNAME_SZ];
  //const char *tld;
  uint8_t opcode;
  uint8_t rcode;
  unsigned int malformed:1;
  DNSLOG_BOOL qr;
  DNSLOG_BOOL rd;		/* set if RECUSION DESIRED bit is set */
  struct {
    DNSLOG_BOOL found;	/* set if we found an OPT RR */
    DNSLOG_BOOL DO;	/* set if DNSSEC DO bit is set */
    uint8_t version;	/* version field from OPT RR */
  } edns;
  /* ... */
};

#define ipv6 ip_handler.IPV.IPv6
#define ipv4 ip_handler.IPV.IPv4
#define inet_af ip_handler.af
#endif



