/*
  $Id: DNSLog.h,v 1.7 2007/05/05 16:39:01 calle Exp $

  Copyright(c) 2007 by Carl Olsen
  
  

*/
#ifndef DNS_LOG
#define DNS_LOG
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>


typedef enum 
  {
    FALSE=0,
    TRUE=1,
  }DNSLOG_BOOL;


#include "DNSLog_Int.h"


/* 
   This will be the proper structure for
   sqlite to take care of
*/
#define DNS_LOG_OVERWRITE 0
#define DNS_LOG_NOT_OVERWRITE 1

#define DNS_LOG_DEFAULT_REPLY_TABLE "R"
#define DNS_LOG_DEFAULT_QUERY_TABLE "Q"







/*
  
*/
typedef int (QVSR) (void *,dns_message *);
/*
  Callback funktions for 
  E1 and E2
*/

typedef char *(E1_fun)(const dns_message *, void *);
typedef char *(E2_fun)(const dns_message *, void *);



#define DNS_LOG_QUERY 0
#define DNS_LOG_REPLY 1
#define DNS_LOG_ERROR 2



/*
  Error messages
*/


#define DNS_LOG_OK 0
#define DNS_LOG_FAILED_MEMORY_ALLOC 1
#define DNS_LOG_FAILED_MEMORY_ALLOC_STR "Failed to allocate memory"

#define DNS_LOG_FAILED_OPEN_DB 2
#define DNS_LOG_FAILED_OPEN_DB_STR "Failed to open database for writing"

#define DNS_LOG_NO_DB 3
#define DNS_LOG_NO_DB_STR "DB structure was NULL, forgot to open?"

#define DNS_LOG_FILE_NOT_OVERWRITE 4
#define DNS_LOG_FILE_NOT_OVERWRITE_STR "DB file exists and is not overwriteable"

#define DNS_LOG_PREPARE_STATE_ERROR 5
#define DNS_LOG_PREPARE_STATE_ERROR_STR "State error while doing insert, forgot to prepare?"

#define DNS_LOG_MSG_MALFORMED 6
#define DNS_LOG_MSG_MALFORMED_STR "Dns message is malformed, not used in database"

#define DNS_LOG_CP_RAM2DISK_ERROR 7


#define DNS_LOG_DB_ERROR 666
#define DNS_LOG_INTERNAL_ERROR 999


#define DNS_LOG_STATE_OK 0
#define DNS_LOG_STATE_NOT_OK -1

#define DNS_LOG_NULL_POINTER -2
#define DNS_LOG_NULL_POINTER_STR "The reffered object is NULL"

int DNSLog_open(void **,const char *,int ,const char *,char **);
int DNSLog_prepare(void *, char **);
int DNSLog_insert_dns_message(void *, dns_message *,QVSR *,void *,char **);
int DNSLog_close(void *,char **);
int DNSLog_extra(void *,E1_fun *,E2_fun *,char **);
int DNSLog_set_table(void *,const char *,const char *,char **);


/*
  Functions to create a dns_message
*/


int DNSLog_create_msg(void **obj,char **errorMsg);
int DNSLog_destroy_msg(void *obj);

int DNSLog_set_timeval(void *obj, struct timeval *tv,char **errorMsg);
struct timeval *DNSLog_get_timeval(void *obj);


int DNSLog_set_addr(void *obj,uint32_t addr,char **errorMsg);
struct in_addr *DNSLog_get_addr(void *obj);

int DNSLog_set_msgID(void *obj,uint16_t id,char **errorMsg);
uint16_t DNSLog_get_msgID(void *obj,char **errorMsg);

int DNSLog_set_src_port(void *obj,uint16_t port,char **errorMsg);
uint16_t DNSLog_get_src_port(void *obj, char **errorMsg);

int DNSLog_set_qtype(void *obj,uint16_t query_type, char **errorMsg);
uint16_t DNSLog_get_qtype(void *obj,char **errorMsg);


uint16_t DNSLog_set_qclass(void *obj, uint16_t query_class,char **errorMsg);
uint16_t DNSLog_get_qclass(void *obj,char **errorMsg);

int DNSLog_set_msglen(void *obj,uint16_t msg_len,char **errorMsg);
uint16_t DNSLog_get_msglen(void *obj,char **errorMsg);

int DNSLog_set_qname(void *obj, const char *query_name, char **errorMsg);
char *DNSLog_get_qname(void *obj,char **errorMsg);

int DNSLog_set_opcode(void *obj,uint8_t opcode,char **errorMsg);
uint8_t DNSLog_get_opcode(void *obj,char **errorMsg);

int DNSLog_set_rcode(void *obj,uint8_t rcode,char **errorMsg);
uint8_t DNSLog_get_rcode(void *obj,char **errorMsg);

int DNSLog_set_isQuery(void *obj,DNSLOG_BOOL isQ,char **errorMsg);
DNSLOG_BOOL DNSLog_get_isQuery(void *obj,char **errorMsg);

int DNSLog_set_isRecursive(void *obj,DNSLOG_BOOL isRec,char **errorMsg);
DNSLOG_BOOL DNSLog_get_Recursive(void *obj,char **errorMsg);

int DNSLog_set_edns_opt_RR(void *obj,DNSLOG_BOOL isFound,char **errorMsg);
DNSLOG_BOOL DNSLog_get_edns_opt_RR(void *obj,char **errorMsg);

int DNSLog_set_edns_DO(void *obj, DNSLOG_BOOL isSet, char **errorMsg);
DNSLOG_BOOL DNSLog_get_edns_DO(void *obj,char **errorMsg);

int DNSLog_set_edns_version(void *obj, uint8_t version, char **errorMsg);
uint8_t DNSLog_get_edns_version(void *obj,char **errorMsg);









//#define _TIME_INDEX 

#endif
