/* 
   $Id: dns2db.c,v 1.14 2007/07/06 13:59:17 calle Exp $
*/
#include "dns2db_config.h"
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



#include "dns2db.h"
#include "read_pcap.h"
#include "arg_handle.h"
#include "DNSLog.h"

#include "e_filter.h"

/*
  packet is a question,
  so we use ldns_rr_list to get hold of information
  about the question..
*/



bool handle_question(ldns_rr_list *rr_list,void *msg)
{
  bool ret = false;
  char *errorMsg=NULL;
  ldns_rr *rr=NULL;
  ldns_buffer *data= NULL;
  ldns_rdf *rdf = NULL;

  
  /*
    Right now i cant handle multiple
    rr's from one message
  */


  
  while((rr=ldns_rr_list_pop_rr(rr_list)))     
    {
  
      
      if(DNSLog_set_qtype(msg,ldns_rr_get_type(rr),&errorMsg) != DNS_LOG_OK)
	{
	  fprintf(stderr,"Error: %s \n",errorMsg);
	  
	  exit(EXIT_FAILURE);
	}

      
      if(DNSLog_set_qclass(msg,ldns_rr_get_class(rr),&errorMsg) != DNS_LOG_OK)
	{
	  fprintf(stderr,"Error: %s \n",errorMsg);
	  exit(EXIT_FAILURE);
	}
      
      
      if((rdf = ldns_rr_owner(rr)))
	{
	  
	  /*
	    Only DNAMES are handled at this time.
	    So we get the Type if the type is a dname
	    we create a new buffer, and then get the
	    dname string from the rdf and insert that into
	    the buffer..And finally add it to DNSLog
	    
	  */

	  //if(ldns_rr_get_type(rr) == LDNS_RDF_TYPE_DNAME)
	  // {
	      data = ldns_buffer_new(256);
	      
	      ldns_rdf2buffer_str_dname(data,rdf);
	      
	      
	      if(DNSLog_set_qname(msg,ldns_buffer_export(data),
				  &errorMsg) != DNS_LOG_OK)
		{
		  fprintf(stderr,"Error: %s \n",errorMsg);
		  
		  exit(EXIT_FAILURE);
		  
		}
	      else
		{

		  ret = true;
		}
	      
	      /*
		We dont need the buffer anymore
	      */
	      ldns_buffer_free(data);
	      
	      //  }
	}
	
    } /* End of while */
  

  return ret;
}


  


/*
  Setting the address part
*/


static void *is_src_address(void *msg,dns_package *pkg,DNSLOG_BOOL q,char **errorMsg)
{
  int af=AF_INET; 
  struct in6_addr *in6 = NULL;
  struct in_addr *in4 = NULL;




  if(pkg->IPV == IPV4) 		/* Its ipv4 */
    {
      if(q == TRUE) 		/* We need the source */
	{
	  in4 = &pkg->ip_hdr.ip4->ip_dst;
	}
      else
	{
	  in4 = &pkg->ip_hdr.ip4->ip_src;
	}
      if(DNSLog_set_client_addr(msg,&in4->s_addr,AF_INET,errorMsg) != DNS_LOG_OK)
      {
	fprintf(stderr,"Error: %s \n",errorMsg);
	exit(EXIT_FAILURE);
      }
      
    }
  else
    {
      if( q == TRUE)
	{
	  	  
	  in6 = &pkg->ip_hdr.ip6->ip6_dst;
	  
	}
      else
	{
	  //test = pkg->ip_hdr.ip6;
	  in6 = &pkg->ip_hdr.ip6->ip6_src;
	}
      if(DNSLog_set_client_addr(msg,&in6->s6_addr,AF_INET6,errorMsg) != DNS_LOG_OK)
      {
	fprintf(stderr,"Error: %s \n",errorMsg);
	exit(EXIT_FAILURE);
      }
	
    }

  
  return msg;
}


/* 
   Create a msg to be inserted into
   DNSLog
*/

void *create_msg(dns_package *pkg)
{
  char *errorMsg;
  void *msg = NULL;
  struct ip *client_ip_struct = pkg->ipV4_hdr;

  uint16_t port;
  ldns_rr_list *ldns_rr=NULL;
    
  
  if(DNSLog_create_msg(&msg,&errorMsg) != DNS_LOG_OK)
    {
      fprintf(stderr,"Error: %s \n",errorMsg);
      exit(EXIT_FAILURE);
    }

  if(DNSLog_set_msglen(msg,ldns_pkt_size(pkg->pkt),&errorMsg) != DNS_LOG_OK)
    {
      fprintf(stderr,"Error: %s \n",errorMsg);
      exit(EXIT_FAILURE);
    }
  
  

  
  if(DNSLog_set_timeval(msg,(struct timeval *)pkg->pcap_hdr,&errorMsg) != DNS_LOG_OK)
    {
      fprintf(stderr,"Error: %s \n",errorMsg);
      exit(EXIT_FAILURE);
    }
 
  /*
    If the package is a query we
    save the source otherwise we are intrested in the 
    destination. Hopefully we know what our dns ip address is.
  */



  if(ldns_pkt_qr(pkg->pkt) == true)
    {
      /*
	Packet is a query!
	Get the source address and the source port
	from the source.


	 src_port
	------ 	       -----  
	|Src |-----Q-->|dns|
	|    |<----A---|   |
	------ 	       ----- 
         dst_port   
		    
	 This is weird??
	 Why ip_dst and udp->source??
      */	    
      
      if(DNSLog_set_isQuery(msg,TRUE,&errorMsg) != DNS_LOG_OK)
	{
	  fprintf(stderr,"Error: %s\n",errorMsg);
	}
      port = htons(pkg->udp_hdr->dest);
      msg=is_src_address(msg,pkg,TRUE,&errorMsg);
      //      client_ip_addr = client_ip_struct->ip_dst;

	
    }		    
  else		    
    {		    
      /*
	Packet is a Answere!	
      */
      
      
      
      if(DNSLog_set_isQuery(msg,FALSE,&errorMsg) != DNS_LOG_OK)
	{
	  fprintf(stderr,"Error: %s\n",errorMsg);
	}
      
      port = htons(pkg->udp_hdr->source);
      msg=is_src_address(msg,pkg,FALSE,&errorMsg);
      

      
    }		        

  
  /*
    Save the question part of the packet.
  */
  
  ldns_rr = ldns_pkt_question (pkg->pkt);
  handle_question(ldns_rr,msg);
  

  

  
			 
/*   if(DNSLog_set_addr(msg,client_ip_addr.s_addr,&errorMsg) != DNS_LOG_OK) */
/*     { */
/*       fprintf(stderr,"Error: %s \n",errorMsg); */
/*       exit(EXIT_FAILURE); */
/*     } */
  
  /* 
     insert port to the message,,
  */
  if(DNSLog_set_src_port(msg,port,&errorMsg) != DNS_LOG_OK)
    {
      fprintf(stderr,"Error: %s \n",errorMsg);
      exit(EXIT_FAILURE);
    }
  
  /*
    Get the message id from the 
  */
  
  if(DNSLog_set_msgID(msg,ldns_pkt_id(pkg->pkt),&errorMsg) != DNS_LOG_OK)
    {
      fprintf(stderr,"Error: %s \n",errorMsg);
      exit(EXIT_FAILURE);
    }


  if(DNSLog_set_opcode(msg,ldns_pkt_get_opcode(pkg->pkt),&errorMsg) 
     != DNS_LOG_OK)
    {
      fprintf(stderr,"Error: %s \n",errorMsg);
      exit(EXIT_FAILURE);
    }

  if(DNSLog_set_rcode(msg,ldns_pkt_get_rcode(pkg->pkt),&errorMsg) 
     != DNS_LOG_OK)
    {
      fprintf(stderr,"Error: %s \n",errorMsg);
      exit(EXIT_FAILURE);
    }
  
  if(DNSLog_set_isRecursive(msg,ldns_pkt_rd(pkg->pkt),&errorMsg)
     != DNS_LOG_OK)
    {
      fprintf(stderr,"Error: %s \n",errorMsg);
      exit(EXIT_FAILURE);
    }

  /*
    Check if edns_udp size is bigger than 0
    Then we process ...
    Actually this could be pretty intresting to see..
    But we leave it for later work
    
  */


  if(ldns_pkt_edns_udp_size(pkg->pkt) > 0)
    {
      if(DNSLog_set_edns_opt_RR(msg,TRUE,&errorMsg) != DNS_LOG_OK)
	{
	  fprintf(stderr,"Error: %s \n",errorMsg);
	  exit(EXIT_FAILURE);
	}
    }
  else
    {

      if(DNSLog_set_edns_opt_RR(msg,FALSE,&errorMsg) != DNS_LOG_OK)
	{
	  fprintf(stderr,"Error: %s \n",errorMsg);
	  exit(EXIT_FAILURE);
	}
    }



      
  
  if(DNSLog_set_edns_DO(msg,ldns_pkt_edns_do(pkg->pkt),&errorMsg)
     != DNS_LOG_OK)
    {
      fprintf(stderr,"Error: %s \n",errorMsg);
      exit(EXIT_FAILURE);
    }
  

  if(DNSLog_set_edns_version(msg,ldns_pkt_edns_version(pkg->pkt),&errorMsg)
     != DNS_LOG_OK)
    {
      fprintf(stderr,"Error: %s \n",errorMsg);
      exit(EXIT_FAILURE);
    }

  
  


  return msg;
}

/* 
   The callback function is used to 
   insert dns_messages into the db.
   
*/


int message_callback(dns_package *pkt, void *extra)
{
  int ret= READ_PCAP_END;
  char *errBuf = NULL;

  dns_message *msg = NULL;
  msg = (dns_message *)create_msg(pkt);
  
  

  





  if(extra != NULL)
     {
       if(DNSLog_insert_dns_message(extra,msg,NULL,NULL,&errBuf) != 
	  DNS_LOG_OK)
	 {
	   printf("Error: Could not insert: %s \n",errBuf);
	   printf("%s\n",msg->qname);
	   
	   exit(EXIT_FAILURE);
	 }
       else
	 {
	   ret = READ_PCAP_END;
	 }
     }
  
  //  printf("%s\n",msg->qname);
  DNSLog_destroy_msg(msg);
  ret = READ_PCAP_CONT;
  return ret;
}

/*
  This function will add the bpf program (if there)
  execute the pcap_read and then free
  the reader_obj
*/

void exec_pcap_read(arg_struct *ar,void *reader_obj,void *sql_obj)
{
  char *errBuf;
  if(ar->bpf != NULL)
    {
      if(read_pcap_bpf_filter(reader_obj,ar->bpf,&errBuf) < 0)
	{
	  fprintf(stderr,"%s \n",errBuf);
	  exit(EXIT_FAILURE);
	}
    }
	  
	  
  read_pcap_exec(reader_obj,message_callback,sql_obj);
  read_pcap_free(reader_obj);
}

/*
  This function will check if the
  arg_structure has any of replies or queries only
  set, and if ít will set the QRA in read_pcap
  by calling read_pcap_Set_QRA.
*/

void set_QRA_options(void *reader_obj,arg_struct *ar)
{
  char *errBuf;
  
  /* 
     If queries only is set and replies not
     set QRA=Q
  */
  if(ar->qo == 1 && ar->ro != 1)
    {  
      if(read_pcap_Set_QRA(reader_obj,Q,&errBuf) != READ_PCAP_OK)
	{
	  fprintf(stderr,"Error while setting Queries only: %s\n",errBuf);
	  exit(EXIT_FAILURE);
	}
      printf("Will only be storing queries\n");
    }
  /* 
     if replies only is set and queries not
     set QRA=R
  */
  else if(ar->ro == 1 && ar->qo != 1)
    {
      
      if(read_pcap_Set_QRA(reader_obj,R,&errBuf) != READ_PCAP_OK)
	{
	  fprintf(stderr,"Error while setting Queries only: %s\n",errBuf);
	  exit(EXIT_FAILURE);
	}
      printf("Will only be storing replies\n");
    }
  /*
    if both are set just print out a message that this is stupid..
   */  
  else if(ar->ro == 1 && ar->qo == 1)
    {
      printf("Default is setting both queries and replies no need to specify\n");
    }
  /*
    The default is ALL therefor its not necessary 
    to set it...
  */
  else
    {
      printf("Will be storing both queries and replies\n");
    }
  
}

  
/*
  The point with this function is to run through each of the files
  for which has been addressed by the struct
*/

void file_round_robin(arg_struct *ar,void *sql_obj)
{
  void *reader_obj = NULL;
  char *errBuf=NULL;
  int file_cnt=0;

  
  for(file_cnt=0; file_cnt < ar->nr_files ; file_cnt++)
    {
      if(read_pcap_init(&reader_obj,ar->pcap_files[file_cnt], NULL,&errBuf) == READ_PCAP_OK)
	{
	  //Set question,reply or all (Q,R or A)
	  set_QRA_options(reader_obj,ar);
	  
	  exec_pcap_read(ar,reader_obj,sql_obj);
	}
      else
	{
	  fprintf(stderr,"Failed to initialize pcap_reader on file %s error message: %s \n",
		  ar->pcap_files[file_cnt],errBuf);
	}
	  
    }
}	  



/*
  =======================

  Initialize DNSLog..
*/

void *db_init(arg_struct *ar)
{
  void *db_obj;
  char *db_use;
  char *errBuf;
  
  int overwrite = DNS_LOG_NOT_OVERWRITE;

  if(ar->overwrite == 1)
    overwrite = DNS_LOG_OVERWRITE;
     
    
      
  
  if(ar->database != NULL)
    {
      db_use = ar->database;
    }
  else
    {
      db_use = strndup(DEFAULT_DB,strlen(DEFAULT_DB));
    }
  
  if(DNSLog_open(&db_obj,db_use,overwrite,NULL,&errBuf) != DNS_LOG_OK)
    {
      
      fprintf(stderr,"Error: could not open database: %s \n",errBuf);
      exit(EXIT_FAILURE);

    }
  
  return db_obj;
}

/*
  =======================
  preparation of db
  =======================
*/

void db_prepare(void *db_obj,arg_struct *ar)
{
  char *errBuf;
  
  /*
    Check if we have new tables...
  */
  if(ar->q_table != NULL || ar->r_table != NULL)
    {
      if(DNSLog_set_table(db_obj,ar->q_table,ar->r_table,&errBuf) != DNS_LOG_OK)
	{
	  fprintf(stderr,"Error: Could not set table names: %s\n",errBuf);
	  exit(EXIT_FAILURE);
	}
    }
	
      
  
  if(DNSLog_prepare(db_obj,&errBuf) != DNS_LOG_OK)
    {
      fprintf(stderr,"Error: Could not prepare database: %s\n",errBuf);
      exit(EXIT_FAILURE);
    }
}

/*
  =======================
  Set the filter functions to the db_obj
  =======================
*/

 void db_set_filter_func(void *sql_obj,arg_struct *arg)
{ 
  char *errBuf=NULL;
  E1_fun *e1_function = NULL;
  E2_fun *e2_function = NULL;
  
  //E1
  if(e1_filter_compile(arg->q_regexp,&errBuf) < 0)
    {
      fprintf(stderr,"Error qname regexp: %s\n",errBuf);
      exit(EXIT_FAILURE);
    } 
  
  e1_function = (E1_fun *)e1_filter_function(&errBuf);
  
  if(errBuf != NULL)
    {
      fprintf(stderr,"Error getting qname function: %s\n",errBuf);
      exit(EXIT_FAILURE);
    }


  //E2
  if(e2_filter_compile(arg->src_regexp,&errBuf) < 0)
    {
      fprintf(stderr,"Error compiling net regexp: %s\n",errBuf);
      exit(EXIT_FAILURE);
    }
  e2_function = (E2_fun *) e2_filter_function(&errBuf);
  
  if(errBuf != NULL)
    {
      fprintf(stderr,"Error getting qname function: %s\n",errBuf);
      exit(EXIT_FAILURE);
    }

  if(DNSLog_extra(sql_obj,e1_function,e2_function,&errBuf) != DNS_LOG_OK)
    {
      fprintf(stderr,"Error inserting e functions: %s",errBuf);
      exit(EXIT_FAILURE);
    }
}
  
  
    
      



/*
  =======================
*/

int main(int argc, char *argv[])
{
  char *errorMsg;
  void *sql_obj;
  arg_struct *ar=check_options(argc,argv);
  
  sql_obj = db_init(ar);
  db_set_filter_func(sql_obj,ar);  
  db_prepare(sql_obj,ar);
  
  file_round_robin(ar,sql_obj);
  
  if(DNSLog_close(sql_obj,&errorMsg) != DNS_LOG_OK)
    {
      fprintf(stderr,"Error: could not close db %s\n",errorMsg);
      exit(EXIT_FAILURE);
    }
  e_filter_free();		/* Free the filter regexp... */
  
  return 1;
}



	
	
	
	    
      



    
    
    
