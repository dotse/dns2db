#include <stdio.h>
#include <stdlib.h>
#include "DNSLog.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "config.h"




char *insert_e(const dns_message *m,void *arg)
{
  int qn_len = strlen(m->qname);
  char *e1_col = malloc(qn_len+1);
  bzero(e1_col,qn_len+1);
  strncpy(e1_col,m->qname,qn_len);
  
  return e1_col;
}
  
  

dns_message *make_m_q()
{

  dns_message *m=malloc(sizeof(dns_message));
  char *q_name = strdup("www.sunet.se");
  struct in_addr *client = malloc(sizeof(struct in_addr));
  char *errorMsg;
  
  bzero(m->qname,MAX_QNAME_SZ);
  
  inet_pton(AF_INET,"222.111.223.12",client);
  
  DNSLog_set_client_addr((void *) m,&client->s_addr,AF_INET,&errorMsg);

  m->src_port = 53;
  m->qtype = 12;
  m->qclass = 3;
  m->msglen = 123;

  strcpy(m->qname,q_name);
  
  //m.tld = ".se";
  m->opcode = 'U';
  m->rcode = '0';
  m->malformed = -1;
  m->qr =0;
  m->rd = 1;
  m->edns.found = -1;
  m->edns.DO = -1;
  m->edns.version = '2';
  return m;
}


dns_message *make_m_r()
{
  dns_message *m=malloc(sizeof(dns_message));  
  
  char *q_name = "www.bogus.se";  
  struct in6_addr client;
  char *errorMsg;

  
  inet_pton(AF_INET6,"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",&client);
  
  DNSLog_set_client_addr((void *) m,client.s6_addr,AF_INET6,&errorMsg);




  //  inet_aton("111.111.123.12",&(m.client_ipv4_addr));
  
  m->ts.tv_sec=1234;
  m->src_port = 53;
  m->qtype = 12;
  m->qclass = 3;
  m->msglen = 123;

  strcpy(m->qname,q_name);
  
  //m.tld = ".se";
  m->opcode = 'U';
  m->rcode = '0';
  m->malformed = -1;
  m->qr =1;
  m->rd = 1;
  m->edns.found = -1;
  m->edns.DO = -1;
  m->edns.version = '2';
  return m;
}


int main(int args,char *argv[])
{
  void *db = NULL;
  char *errorMsg = NULL;
  char *file= "dnslog.db";
  int ret;
  dns_message *msg;
  
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
  
  msg=make_m_q();
  
  DNSLog_insert_dns_message(db,msg,NULL,NULL,&errorMsg);
  //DNSLog_insert_dns_message(db,msg,NULL,NULL,&errorMsg);
  DNSLog_destroy_msg(msg);

  //msg=make_m_r();
  
  //DNSLog_insert_dns_message(db,msg,NULL,NULL,&errorMsg);
  DNSLog_close(db,&errorMsg);
  
  return 1;
}




  
