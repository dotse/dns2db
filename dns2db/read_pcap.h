
#ifndef _READ_PCAP_H
#define _READ_PCAP_H
#include "dns2db.h"

typedef enum 
  {
    Q,
    R,
    A
  }pkg_capture;

#define READ_PCAP_OK 1

#define READ_PCAP_NO_FILE -1
#define READ_PCAP_NO_FILE_STR "Pcap file not found"

#define READ_PCAP_FAILED_OFFLINE -2

#define READ_PCAP_UNSOPPORTED_LINK -3
#define READ_PCAP_UNSOPPORTED_LINK_STR "Unsupported link layer"

#define READ_PCAP_BPF_COMPILE -4
#define READ_PCAP_BPF_COMPILE_STR "Bpf compilation failed"

#define READ_PCAP_BPF_SETFILTER -5
#define READ_PCAP_BPF_SETFILTER_STR "Bpf setfilter failed"

#define READ_PCAP_NO_READ_PCAP -6
#define READ_PCAP_NO_READ_PCAP_STR "read pcap object is null or is not supported"

/* 
   Internal header parsing errors
*/
#define READ_PCAP_PCAP_HEADER_LEN_PROBLEM -7 
#define READ_PCAP_ETHER_HEADER_LEN_PROBLEM -8
#define READ_PCAP_UNKOWN_ETHER_TYPE -9
#define READ_PCAP_ETHER_UNSUFFICIENT_LEN -10
#define READ_PCAP_IP_UNKOWN_PROTO -11
#define READ_PCAP_IP_FRAGMENT -12
#define READ_PCAP_WRONG_PORT -13
#define READ_PCAP_DNS_PKT_ERROR -14

#ifndef ETHER_HDR_LEN
#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_LEN 2
#define ETHER_HDR_LEN (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)
#endif
#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q	0x8100
#endif

#define READ_PCAP_CONT 1
#define READ_PCAP_END 0

typedef int (HMSG) (dns_package *,void *);

int read_pcap_init(void **,const char *, char *,char **);
int read_pcap_exec(void *read_obj,HMSG *,void *);
int read_pcap_bpf_filter(void *,char *,char **);
void read_pcap_free(void *);
int read_pcap_Set_QRA(void *,pkg_capture ,char **);


#ifndef T_OPT
#define T_OPT 41	/* OPT pseudo-RR, RFC2761 */
#endif

#ifndef T_AAAA
#define T_AAAA 28
#endif

#ifndef C_CHAOS
#define C_CHAOS 3
#endif

#endif
