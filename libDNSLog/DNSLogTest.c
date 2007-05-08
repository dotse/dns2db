#include <stdio.h>
#include <stdlib.h>
#include "DNSLog.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "config.h"

static dns_message m;


char *insert_e(const dns_message *m,void *arg)
{
  int qn_len = strlen(m->qname);
  char *e1_col = malloc(qn_len);
  
  strncpy(e1_col,m->qname,qn_len);
  
  return e1_col;
}
  
  

void make_m_q()
{
  char *q_name = "www.sunet.se";

  inet_aton("222.111.223.12",&(m.client_ipv4_addr));

  m.src_port = 53;
  m.qtype = 12;
  m.qclass = 3;
  m.msglen = 123;

  strcpy(m.qname,q_name);
  
  //m.tld = ".se";
  m.opcode = 'U';
  m.rcode = '0';
  m.malformed = -1;
  m.qr =0;
  m.rd = 1;
  m.edns.found = -1;
  m.edns.DO = -1;
  m.edns.version = '2';
}


void make_m_r()
{
  char *q_name = "www.bogus.se";

  inet_aton("111.111.123.12",&(m.client_ipv4_addr));
  
  m.ts.tv_sec=1234;
  m.src_port = 53;
  m.qtype = 12;
  m.qclass = 3;
  m.msglen = 123;

  strcpy(m.qname,q_name);
  
  //m.tld = ".se";
  m.opcode = 'U';
  m.rcode = '0';
  m.malformed = -1;
  m.qr =1;
  m.rd = 1;
  m.edns.found = -1;
  m.edns.DO = -1;
  m.edns.version = '2';
}


int main(int args,char *argv[])
{
  void *db = NULL;
  char *errorMsg = NULL;
  char *file= "dnslog.db";
  int ret;

  
  ret = DNSLog_open(&db,file,DNS_LOG_OVERWRITE,"TEST",&errorMsg);
  
  if(errorMsg != NULL)
    {
      printf("%s %d\n",errorMsg,ret);
      exit(123);
    }

  ret = DNSLog_set_table(db,"Calle","Nalle",&errorMsg);
  
  if(errorMsg != NULL)
    {
      printf("%s %d\n",errorMsg,ret);
      exit(123);
    }

     
  ret = DNSLog_extra(db,insert_e,insert_e,&errorMsg);
  if(errorMsg != NULL)
    {
      printf("%s %d\n",errorMsg,ret);
      exit(123);
    }


  ret = DNSLog_prepare(db,&errorMsg);
  
  if(errorMsg != NULL)
    {
      printf("%s %d\n",errorMsg,ret);
      exit(123);
    }
  
  make_m_q();
  
  DNSLog_insert_dns_message(db,&m,NULL,NULL,&errorMsg);

  make_m_r();

  DNSLog_insert_dns_message(db,&m,NULL,NULL,&errorMsg);
  DNSLog_close(db,&errorMsg);
  
  return 1;
}




  
