/*
  $Id: DNSLog.c,v 1.5 2007/07/06 13:59:42 calle Exp $

  Copyright(c) 2007 by Carl Olsen
  
  

*/

#include "libTimer.h"
#include "ram2disk.h"
#define _GNU_SOURCE  
#include "DNSLog.h"
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <sqlite3.h>
#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "SQLCommands.h"


#define OPEN_STATE 0;
#define PREPARE_STATE 1
#define INSERT_STATE 2

#define SQL_CMD_SZ 65536
#define FILE_EXISTS 1
#define FILE_NOT_EXISTS 0



/* 
   we start by defining the table names..
   As this is just a prototype we will not care about 
   if the user want to have special names of the table 
   aso. This can be a later advancement..
   
*/

typedef struct {
  char *file_to_use;
  char *temp_file;
  char *perm_file;
  sqlite3 *db;
  E1_fun *fun_e1;
  E2_fun *fun_e2;
  
  struct{
    int open:1;
    int prepare:1;
  } state;

  struct{
    char *query;
    char *reply;
  }table_name;

  struct{
    sqlite3_stmt *q_stmt;  //Prepared statements
    sqlite3_stmt *r_stmt;
  }pre_stmt;
  
} DNSLog_struct;




/*
  create_sql_command 
  input: sqlcommand,arg
  output: parsed_cmd

  create a string of the sql_command

*/

static char * create_sql_command(char *sql_cmd,char *arg)
{
  char *buf=NULL;
  size_t bufSize=strlen(sql_cmd)+strlen(arg);
  
  if((buf = malloc(bufSize*sizeof(char))) == NULL)
    {
      return NULL;
    }
  
  snprintf(buf,bufSize,sql_cmd,arg);
  
  return buf;
}
  
  


/* 
   Internal descition algorithm for 
   query or reply..
   Based on if the rcode is set.
*/

int query_or_reply(void *not_used,dns_message *d_msg)
{
  int ret = DNS_LOG_ERROR;
  if(d_msg != NULL )
    {
      if(d_msg->qr) // is set only if query reply..
	{
	  ret =DNS_LOG_REPLY;
	}
      else
	{
	  ret = DNS_LOG_QUERY;
	}
    }
  
  return ret;
}

static char *get_ip_addr_str(const dns_message *msg)
{
  char *ip_addr;

  if(msg->inet_af == AF_INET)
    {
      /* Ipv4 address */
      ip_addr = malloc(INET_ADDRSTRLEN);
      inet_ntop(msg->inet_af,(void *) &msg->ipv4,ip_addr,INET_ADDRSTRLEN);

    }
  /* Ipv6 address */
  if(msg->inet_af == AF_INET6)
    {
      ip_addr = NULL;
      ip_addr = malloc(INET6_ADDRSTRLEN);
      inet_ntop(msg->inet_af,(void *) &msg->ipv6,ip_addr,INET6_ADDRSTRLEN);
    }
  
  return ip_addr;
}
  




/*
  
  First prepare a statement..
  
  Reset the statement..

  Clear the bindings.
  
  Bind it to a (new) value...There are either text or int..

  Step through.

  and finally finalize the whole thing..
  
*/


static int prepare_sql_stmt(sqlite3 *db,sqlite3_stmt **stmt,const char *sql_command,char **errorMsg)
{
  int rc = DNS_LOG_MSG_FAILED_PREPARE;
  int rv;
  

  
  //char *zErrorMsg=0;  Not using ...
  //  int i_size_char = sizeof(char);
  rv=sqlite3_prepare_v2(db,sql_command,strlen(sql_command),stmt,0);
  
  if(rv != SQLITE_OK)
    {
      *errorMsg = strndup(DNS_LOG_MSG_FAILED_PREPARE_STR,strlen(DNS_LOG_MSG_FAILED_PREPARE_STR));
    }
  else
    {
      rc = DNS_LOG_OK;
    }
  
  return rc;
  
  
}

//First index is always 1

static int bind_sql_stmt_text(sqlite3_stmt *stmt,int index,char *sql_val,char **errorMsg)
{  
  int rc = DNS_LOG_MSG_FAILED_BIND_TEXT;
  int rv;



  //I will use -1 to terminate on \0.though this should probably be changed...
  if( (rc=sqlite3_bind_text(stmt,index,sql_val,-1,free)) == SQLITE_OK)
    {
      rc = DNS_LOG_OK;
    }
  else
    {
      fprintf(stderr,"Unable to bind %d\n",rc);
      *errorMsg = strndup(DNS_LOG_MSG_FAILED_BIND_TEXT_STR,strlen(DNS_LOG_MSG_FAILED_BIND_TEXT_STR));
    }
  
  return rc;
}

/*
  Bind integers.
*/
static int bind_sql_stmt_int(sqlite3_stmt *stmt,int index,int num,char **errorMsg)
{
  int rc = DNS_LOG_MSG_FAILED_BIND_INT;
  int rv;


  //I will use -1 to terminate on \0.though this should probably be changed...
  if( (rv=sqlite3_bind_int(stmt,index,num)) == SQLITE_OK)
    {
      rc = DNS_LOG_OK;
    }
  else
    {
      *errorMsg = strndup(DNS_LOG_MSG_FAILED_BIND_INT_STR,strlen(DNS_LOG_MSG_FAILED_BIND_INT_STR));
    }
  
  return rc;
}


/*
  sqlite3_step..
*/

static int exec_sql_stmt(sqlite3_stmt *stmt,char **errorMsg)
{
  int rc = DNS_LOG_MSG_SQL_EXEC;
  int rv = 0;


  
  if((rv=sqlite3_step(stmt)) == SQLITE_DONE)
    {
      rc = DNS_LOG_OK;
    }
  else
    {
      
      fprintf(stderr,"sqlite3_step: %d\n",rv);
      *errorMsg = strndup(DNS_LOG_MSG_SQL_EXEC_STR,strlen(DNS_LOG_MSG_SQL_EXEC_STR));
    }
  
  return rc;
}


/*
  Finalize a statment
  
*/
static int finalize_sql_stmt(sqlite3_stmt *stmt,char **errorMsg)
{
  int rc = DNS_LOG_MSG_SQL_FINALIZE;
  int rv;
  

  if((rv=sqlite3_finalize( stmt)) == SQLITE_OK)
    {
      rc = DNS_LOG_OK;
    }
  else
    {
      rc = DNS_LOG_MSG_SQL_FINALIZE;
      fprintf(stderr,"sqlite3_finalize: %d\n",rv);
      *errorMsg = strndup(DNS_LOG_MSG_SQL_FINALIZE_STR,strlen(DNS_LOG_MSG_SQL_FINALIZE_STR));
    }
  
  return rc;
}
     
/*
  Clear bindings
  Set all parameters in the compiled SQL statement back to NULL...
*/

static int clear_bindings_sql_stmt(sqlite3_stmt *stmt,char **errorMsg)
{
  int rc = DNS_LOG_MSG_CLEAR_BINDS;
  int rv;
  
  
  if((rv = sqlite3_clear_bindings(stmt)) == SQLITE_OK)
    {
      rc = DNS_LOG_OK;
    }
  else
    {
      fprintf(stderr,"sqlite3_clear_bindings: %d\n",rv);
      *errorMsg = strndup(DNS_LOG_MSG_CLEAR_BINDS_STR,strlen(DNS_LOG_MSG_CLEAR_BINDS_STR));
    }
  
  return rc;
}

/*
  Reset the sqlite3_stmt
  resets a prepared sql statement back to its initial state, ready to be 
  re-executed. Any SQL statement variables that had values boud 
  to them using the sqlite3_bind_* API retains their values.
*/

static int reset_sql_stmt(sqlite3_stmt *stmt, char **errorMsg)
{

  int rc = DNS_LOG_MSG_SQL_RESET;
  int rv;
  
  if((rv = sqlite3_reset(stmt)) == SQLITE_OK)
    {
      rc = DNS_LOG_OK;
    }
  else
    {
      fprintf(stderr,"sqlite3_reset: %d\n",rv);
      *errorMsg = strndup(DNS_LOG_MSG_SQL_RESET_STR,strlen(DNS_LOG_MSG_SQL_RESET_STR));
    }
  
  return rc;
}
	      
  
      


//--------------------
/*
  Inserts the dns_message to the database..
  These two functions are very similair, and maybe we can break them up
  to make smaller...but not now..
*/

static int prepare_q_stmt(DNSLog_struct *db_s,char **errorMsg)
{
  char sql_cmd[SQL_CMD_SZ];
  int rc;
  sqlite3_stmt *stmt;
  
  bzero(sql_cmd,SQL_CMD_SZ*sizeof(char));
  
  snprintf(sql_cmd,SQL_CMD_SZ,
	   SQL_COMMAND_Q_INSERT,
	   db_s->table_name.query);
  
  rc = prepare_sql_stmt(db_s->db,&stmt,sql_cmd,errorMsg);

  if(rc == DNS_LOG_OK)
    db_s->pre_stmt.q_stmt = stmt; // And finally add it to the DNSLog_strcture...
  
  

  return rc;
}

 
/*
  prepare Reply statment
*/

static int prepare_r_stmt(DNSLog_struct *db_s,char **errorMsg)
{
  char sql_cmd[SQL_CMD_SZ];
  int rc;
  sqlite3_stmt *stmt;
  
  bzero(sql_cmd,SQL_CMD_SZ*sizeof(char));
  
  snprintf(sql_cmd,SQL_CMD_SZ,
	   SQL_COMMAND_R_INSERT,
	   db_s->table_name.reply);
  
  rc = prepare_sql_stmt(db_s->db,&stmt,sql_cmd,errorMsg);

  if(rc == DNS_LOG_OK)
    db_s->pre_stmt.r_stmt = stmt;
  
  

  return rc;
}
     


static int insert_q_msg(DNSLog_struct *db,dns_message *msg,void *funArg,char **errorMsg)
{
  int ret =DNS_LOG_INTERNAL_ERROR;
  char *e1=NULL;
  char *e2=NULL;
  char *ipv4_ascii = get_ip_addr_str(msg);
  int ip_addr_raw = 0;
  
  int rc = 0;


  
  if(db->fun_e1 != NULL )
    {
      e1 = db->fun_e1(msg,funArg);
    }
    
  
  if(db->fun_e2 != NULL )
    {
      e2 = db->fun_e2(msg,funArg);
    }
  
  //setting the right name of the table.
      
      //So we inserted a time
  rc = bind_sql_stmt_int(db->pre_stmt.q_stmt,                //Statement
			     1,                   //Index
			     (int)msg->ts.tv_sec, //Number
			     errorMsg);          //ErrorMessage
      
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
      
      rc = bind_sql_stmt_int(db->pre_stmt.q_stmt,                //Statement
			     2,                   //Index 2
			     msg->msg_id,        // Message ID
			     errorMsg);          //ErrorMessage
      
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
      

      if(msg->inet_af == AF_INET6)
	{
	  ip_addr_raw =0;
	}
      else
	{
	  ip_addr_raw=msg->ipv4.s_addr;
	}
      
      rc = bind_sql_stmt_int(db->pre_stmt.q_stmt,	                          //Statement
			     3,                                   //Index 3
			     ip_addr_raw,                           // Client address raw..??
			     errorMsg);                           //ErrorMessage
      
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
	
      rc = bind_sql_stmt_text(db->pre_stmt.q_stmt,                                //Statement
			      4,                                   //Index 4
			      ipv4_ascii,                          // Client address in ascii
			      errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
      
      rc = bind_sql_stmt_int(db->pre_stmt.q_stmt,                 //Statement
			      5,                                   //Index 5
			      msg->src_port,                       // Src port
			      errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}

      

      rc = bind_sql_stmt_int(db->pre_stmt.q_stmt,                 //Statement
			      6,                                   //Index 6
			      msg->qtype,                          // Query type
			      errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}


      rc = bind_sql_stmt_int(db->pre_stmt.q_stmt,                 //Statement
			      7,                                  //Index 6
			      msg->qclass,                        // Query classification
			      errorMsg);                          //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
      
      
      rc = bind_sql_stmt_int(db->pre_stmt.q_stmt,                  //Statement
			      8,                                   //Index 8
			      msg->msglen,                         // message length
			      errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
      
      
      
      
      rc = bind_sql_stmt_text(db->pre_stmt.q_stmt,                  //Statement
			     9,                                   //Index 9
			     strndup(msg->qname,strlen(msg->qname)),// Query name, need to copy it..
			     errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}

      rc = bind_sql_stmt_int(db->pre_stmt.q_stmt,                  //Statement
			     10,                                   //Index 10
			     msg->opcode,                         // opcode
			     errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}

      rc = bind_sql_stmt_int(db->pre_stmt.q_stmt,                  //Statement
			     11,                                   //Index 11
			     msg->rd,                              // Recursive desired flag 
			     errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}


      rc = bind_sql_stmt_int(db->pre_stmt.q_stmt,                  //Statement
			     12,                                   //Index 12
			     msg->edns.found,                      // Recursive desired flag 
			     errorMsg);                            //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}

      rc = bind_sql_stmt_int(db->pre_stmt.q_stmt,                  //Statement
			     13,                                   //Index 13
			     msg->edns.DO,                         // DO bit
			     errorMsg);                            //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}

      rc = bind_sql_stmt_int(db->pre_stmt.q_stmt,                  //Statement
			     14,                                   //Index 14
			     msg->edns.version,                    // EDNS version
			     errorMsg);                            //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
      

      rc = bind_sql_stmt_text(db->pre_stmt.q_stmt,                  //Statement
			     15,                                   //Index 15
			     e1,                                   // EXTRA SPACE..Got from function 
			     errorMsg);                            //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
      

      rc = bind_sql_stmt_text(db->pre_stmt.q_stmt,                  //Statement
			      16,                                   //Index 16
			      e2,                                   // EXTRA SPACE..Got from function 
			      errorMsg);                            //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}

      

      return rc;
}


/*
  Insert a reply message in the prepared statment..
*/
static int insert_r_msg(DNSLog_struct *db,dns_message *msg,void *funArg,char **errorMsg)
{
  int ret =DNS_LOG_INTERNAL_ERROR;
  char *e1=NULL;
  char *e2=NULL;
  char *ipv4_ascii = get_ip_addr_str(msg);
  int ip_addr_raw;
  int rc = 0;
  

  
  if(db->fun_e1 != NULL )
    {
      e1 = db->fun_e1(msg,funArg);
    }
    
  
  if(db->fun_e2 != NULL )
    {
      e2 = db->fun_e2(msg,funArg);
    }
  
        
  //So we inserted a time
  rc = bind_sql_stmt_int(db->pre_stmt.r_stmt,      //The Statement
			     1,                   //Index
			     (int)msg->ts.tv_sec, //Number
			     errorMsg);          //ErrorMessage
      
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
      
      rc = bind_sql_stmt_int(db->pre_stmt.r_stmt,                //Statement
			     2,                   //Index 2
			     msg->msg_id,        // Message ID
			     errorMsg);          //ErrorMessage
      
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}

      
      if(msg->inet_af == AF_INET6)
	{
	  ip_addr_raw =0;
	}
      else
	{
	  ip_addr_raw=msg->ipv4.s_addr;
	}

      
      rc = bind_sql_stmt_int(db->pre_stmt.r_stmt,	                          //Statement
			     3,                                   //Index 3
			     ip_addr_raw,        // Client address raw..??
			     errorMsg);                           //ErrorMessage
      
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
	
      rc = bind_sql_stmt_text(db->pre_stmt.r_stmt,                 //Statement
			      4,                                   //Index 4
			      ipv4_ascii,                          // Client address in ascii
			      errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
      
      rc = bind_sql_stmt_int(db->pre_stmt.r_stmt,                 //Statement
			      5,                                   //Index 5
			      msg->src_port,                       // Src port
			      errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}

      

      rc = bind_sql_stmt_int(db->pre_stmt.r_stmt,                 //Statement
			      6,                                   //Index 6
			      msg->qtype,                          // Query type
			      errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}


      rc = bind_sql_stmt_int(db->pre_stmt.r_stmt,                 //Statement
			      7,                                  //Index 6
			      msg->qclass,                        // Query classification
			      errorMsg);                          //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
      
      
      rc = bind_sql_stmt_int(db->pre_stmt.r_stmt,                  //Statement
			      8,                                   //Index 8
			      msg->msglen,                         // message length
			      errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
      
      
      

      
      rc = bind_sql_stmt_text(db->pre_stmt.r_stmt,                  //Statement
			     9,                                   //Index 9
			     strndup(msg->qname,strlen(msg->qname)),// Query name, need to copy it..
			     errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}

      rc = bind_sql_stmt_int(db->pre_stmt.r_stmt,                  //Statement
			     10,                                   //Index 10
			     msg->opcode,                         // opcode
			     errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}

      rc = bind_sql_stmt_int(db->pre_stmt.r_stmt,                  //Statement
			     11,                                   //Index 11
			     msg->rcode,                           // Recursive desired flag 
			     errorMsg);                           //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}


      rc = bind_sql_stmt_int(db->pre_stmt.r_stmt,                  //Statement
			     12,                                   //Index 12
			     msg->rd,                      // Recursive desired flag 
			     errorMsg);                            //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}

      
      rc = bind_sql_stmt_int(db->pre_stmt.r_stmt,                  //Statement
			     13,                                   //Index 12
			     msg->edns.found,                      // Recursive desired flag 
			     errorMsg);                            //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}


      rc = bind_sql_stmt_int(db->pre_stmt.r_stmt,                  //Statement
			     14,                                   //Index 13
			     msg->edns.DO,                         // DO bit
			     errorMsg);                            //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}

      rc = bind_sql_stmt_int(db->pre_stmt.r_stmt,                  //Statement
			     14,                                   //Index 14
			     msg->edns.version,                    // EDNS version
			     errorMsg);                            //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
      

      rc = bind_sql_stmt_text(db->pre_stmt.r_stmt,                  //Statement
			     15,                                   //Index 15
			     e1,                                   // EXTRA SPACE..Got from function 
			     errorMsg);                            //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}
      

      rc = bind_sql_stmt_text(db->pre_stmt.r_stmt,                  //Statement
			      16,                                   //Index 16
			      e2,                                   // EXTRA SPACE..Got from function 
			      errorMsg);                            //ErrorMessage
      if(rc != DNS_LOG_OK)
	{
	  // break out if it didnt work
	  return rc;
	}

      

      return rc;
}

  




  
//--------------------
/* 
   Maybe should do some checking of the file name..
   Maybe later....
*/
static int insert_file_in_struct(DNSLog_struct **log_struct, const char *file,const char *tempF)
{
  int ret = DNS_LOG_INTERNAL_ERROR;
  (*log_struct)->perm_file = NULL;
  (*log_struct)->temp_file = NULL;


  if(( (*log_struct)->perm_file = strndup(file,strlen(file))) == NULL )
    {
      ret = DNS_LOG_FAILED_MEMORY_ALLOC;
    }
  else
    {

      if(tempF != NULL )
	{
	  if(( (*log_struct)->temp_file = strndup(tempF,strlen(tempF))) == NULL)
	    {
	      ret = DNS_LOG_FAILED_MEMORY_ALLOC;
	    }
	  else
	    {
	      /*
		In this case we have a temp file so we want to use that
		one for inserts
	      */
	      (*log_struct)->file_to_use = (*log_struct)->temp_file;
	      ret = DNS_LOG_OK;
	      
	    }

	}
      else
	{
	  /*
	    There does not exists a temp file so we want to use
	    the permanent file
	  */
	  
	  (*log_struct)->file_to_use = (*log_struct)->perm_file;
	  ret = DNS_LOG_OK;
	}
    }
    

  return ret;
 
}


static int file_exists(DNSLog_struct *db_struct)
{
  struct stat buf;
  int ret = FILE_NOT_EXISTS;
  
  if(stat(db_struct->file_to_use,&buf) == 0)
    {
      ret= FILE_EXISTS;
    }
  
  return ret;
}
  
  
    
/*
  Check status 
*/

static int checkStatus(DNSLog_struct *db,int overwrite, char **errorMsg)
{
  int errMsgLen=0;
  int ret = DNS_LOG_INTERNAL_ERROR;
  
  /*
    File exists but should not be overwritten.ERROR
  */
  if(file_exists(db) == FILE_EXISTS && overwrite == DNS_LOG_NOT_OVERWRITE)
    {
      errMsgLen =strlen(DNS_LOG_FILE_NOT_OVERWRITE_STR);
      *errorMsg = malloc(errMsgLen*sizeof(char));
      strncpy(*errorMsg,DNS_LOG_FILE_NOT_OVERWRITE_STR,errMsgLen);
      ret = DNS_LOG_FILE_NOT_OVERWRITE;
    }
  /*
    File exists but should be removed if possible...
  */
  else if(file_exists(db) == FILE_EXISTS && overwrite == DNS_LOG_OVERWRITE)
  {
    
    
    if(remove(db->file_to_use) != 0)
      {
	errMsgLen =strlen(DNS_LOG_FILE_NOT_OVERWRITE_STR);
	*errorMsg = malloc(errMsgLen*sizeof(char));
	strncpy(*errorMsg,DNS_LOG_FILE_NOT_OVERWRITE_STR,errMsgLen);
	ret =  DNS_LOG_FILE_NOT_OVERWRITE;
      }
    else
      {
	/* 
	   Removed the old DB, Good to go...
	*/

	ret = DNS_LOG_OK;
      }
  }
  /*
    File does not exists, which is good..
  */
  else
    {
      ret = DNS_LOG_OK;
    }
      
  return ret;
}

      
      
/*
  The DNSLog_open, creates the DNSLog structure which saves
  the necessary information for further use of the sqlite.
  
  The void argument holds the information of the structure.
  The errorMsg is populated only if there is a errorMessage.
  if temp_file is set this one is used before copying to 
  the permanent place
  
*/
  
int DNSLog_open(void **db_struct,
		const char *file_name,
		int writeCond,
		const char *temp_file,
		char **errorMsg)
{
  int ret = DNS_LOG_OK;
  DNSLog_struct *save_db = malloc(sizeof(DNSLog_struct));
  save_db->state.open =DNS_LOG_STATE_NOT_OK;
  save_db->state.prepare = DNS_LOG_STATE_NOT_OK;
  //Setting the default names..
  save_db->table_name.query = strndup(DNS_LOG_DEFAULT_QUERY_TABLE,
				      strlen(DNS_LOG_DEFAULT_QUERY_TABLE));
  save_db->table_name.reply = strndup(DNS_LOG_DEFAULT_REPLY_TABLE,
				      strlen(DNS_LOG_DEFAULT_REPLY_TABLE));

  
  
  if(save_db == NULL)
    {
      ret = DNS_LOG_FAILED_MEMORY_ALLOC;
      *errorMsg = malloc(strlen(DNS_LOG_FAILED_MEMORY_ALLOC_STR)*sizeof(char));
      strncpy(*errorMsg,DNS_LOG_FAILED_MEMORY_ALLOC_STR,strlen(DNS_LOG_FAILED_MEMORY_ALLOC_STR));
      free(save_db);
      
      return ret;
    }

  ret=insert_file_in_struct(&save_db,file_name,temp_file);
  
  /*
    Check if file exists, havent done that yet!!
  */
  if((ret =checkStatus(save_db,writeCond,errorMsg)) != DNS_LOG_OK)
    {
      return ret;
    }
  
  
  if(sqlite3_open(save_db->file_to_use,&save_db->db) != SQLITE_OK )
    {
      /*
	There could be heaps of errors and it might be a 
	good idea to make this a special
	function and to write each of these....
      */
      *errorMsg = malloc(strlen(DNS_LOG_FAILED_MEMORY_ALLOC_STR)*sizeof(char));

      strncpy(*errorMsg,DNS_LOG_FAILED_MEMORY_ALLOC_STR,strlen(DNS_LOG_FAILED_MEMORY_ALLOC_STR));
      
      
      return DNS_LOG_FAILED_MEMORY_ALLOC;
    }

  //all went well so we place the structure in void pointer...(typecast)
  save_db->state.open = DNS_LOG_STATE_OK;
  save_db->fun_e1 = NULL;
  save_db->fun_e2 = NULL;
  save_db->pre_stmt.q_stmt = NULL;
  save_db->pre_stmt.r_stmt = NULL;
  *db_struct = (void *) save_db;
  
  return ret;
}



      

/*
  All the SQL commands are defined in
  SQLCommands.h.
  This function will create two tables.
  One for queries and one for replies..
 ---------------------------------------- 
*/

		      








static int createTables(DNSLog_struct *db_struct,char **errorMsg)
{
  int msg;
  char *q_table=NULL;
  char *r_table=NULL;
  /*
    Creating Query table, we do not use a callback function for this...
    Right no
    Start a transaction,
    create tables
    and commit
  */
  
  
  //SQL_COMMAND_PRE_CREATE_Q_TABLE
  q_table = create_sql_command(SQL_COMMAND_CREATE_Q_TABLE,db_struct->table_name.query);
  r_table = create_sql_command(SQL_COMMAND_CREATE_R_TABLE,db_struct->table_name.reply);
  
  


  if((msg=sqlite3_exec(db_struct->db,SQL_COMMAND_BEGIN_TR,NULL,NULL,errorMsg)) != SQLITE_OK)
    {
      fprintf(stderr,"Failed to start Transaction return code %d\n",msg);
      return DNS_LOG_DB_ERROR;
    }


  if((msg=sqlite3_exec(db_struct->db,q_table,NULL,NULL,errorMsg)) != SQLITE_OK)
    {
      fprintf(stderr,"Unable to create Query table return code %d\n",msg);
      return DNS_LOG_DB_ERROR;
    }
  
  if((msg=sqlite3_exec(db_struct->db,r_table,NULL,NULL,errorMsg)) != SQLITE_OK)
    {
      fprintf(stderr,"Unable to create Reply table return code %d\n",msg);
      return DNS_LOG_DB_ERROR;
    } 

  free(q_table);
  free(r_table);
  
  return DNS_LOG_OK;
}
  

/*
  ----------------------------------------
*/

static int createIndexers(DNSLog_struct *db_struct,char **errorMsg)
{
  int msg;
  

  
  if((msg=sqlite3_exec(db_struct->db,SQL_COMMAND_E1_INDEX,NULL,NULL,errorMsg)) != SQLITE_OK)
    {
      fprintf(stderr,"Unable to create client index return code %d\n",msg);
      return DNS_LOG_DB_ERROR;
    }
  
  
  if((msg=sqlite3_exec(db_struct->db,SQL_COMMAND_CLIENT_QNAME_INDEX,NULL,NULL,errorMsg)) != SQLITE_OK)
    {
      fprintf(stderr,"Unable to create client index return code %d\n",msg);
      return DNS_LOG_DB_ERROR;
    }
  
  return DNS_LOG_OK;
}
  


/*
  Sets the table names
*/
int DNSLog_set_table(void *db_obj,
		     const char *q_table,
		     const char *r_table,
		     char **errorBuf)
{
  DNSLog_struct *db = (DNSLog_struct *) db_obj;
  
  if(db == NULL || db->state.open == DNS_LOG_STATE_NOT_OK)
    {
      
      *errorBuf = strndup(DNS_LOG_NO_DB_STR,strlen(DNS_LOG_NO_DB_STR));      
      
      return DNS_LOG_NO_DB;
    }
    
  
  if(q_table != NULL)
    {
      free(db->table_name.query);
      db->table_name.query = strndup(q_table,strlen(q_table));
    }
  
  if(r_table != NULL)
    {
      free(db->table_name.reply);
      db->table_name.reply = strndup(r_table,strlen(r_table));
    }
  return DNS_LOG_OK;
  
}  
		     


/*
  This function will prepare the db for writing,
  it will create the tables aso...
  
*/


int DNSLog_prepare(void *db_struct,char **errorMsg)
{
  int ret = DNS_LOG_OK;
  DNSLog_struct *db = (DNSLog_struct *) db_struct;

  
  
  if(db == NULL || db->state.open == DNS_LOG_STATE_NOT_OK)
    {

      *errorMsg = strndup(DNS_LOG_NO_DB_STR,strlen(DNS_LOG_NO_DB_STR));      
      
      return DNS_LOG_NO_DB;
    }


#ifdef SQL_ASYN_PRAGMA
  if((ret=sqlite3_exec(db->db,SQL_ASYN_PRAGMA,NULL,NULL,errorMsg)) != SQLITE_OK)
    {
      fprintf(stderr,"UNABLE TO SET Asynchronous mode: %s\n",*errorMsg);
      return DNS_LOG_DB_ERROR;
    }

#endif
  
  /*
    Both file and db is ok..So now we create the tables....
  */
  

  if((ret=createTables(db,errorMsg)) != DNS_LOG_OK)
    {
      return ret;
    }


  if((ret = prepare_q_stmt(db,errorMsg)) != DNS_LOG_OK)
    {
      return ret;
    }
  
  if((ret = prepare_r_stmt(db,errorMsg)) != DNS_LOG_OK)
    {
      return ret;
    }

  
	
  

  
  
  db->state.prepare = DNS_LOG_STATE_OK;
  return ret;
}



static int malformed_msg(char **errorMsg)
{

  int size = strlen(DNS_LOG_MSG_MALFORMED_STR);
  *errorMsg = malloc(size*sizeof(char));
  
  strncpy(*errorMsg,DNS_LOG_MSG_MALFORMED_STR,size);
  
  return DNS_LOG_MSG_MALFORMED;
}

/*
  

*/



int DNSLog_insert_dns_message(void *sdb, dns_message *msg,
			      QVSR *descFun,void *funArg,char **errorMsg)
{
  int size;
  int ret = DNS_LOG_INTERNAL_ERROR;
  DNSLog_struct *db = (DNSLog_struct *) sdb;
  /*
    Not really good but later fix... ;)
  */
  
  if(db == NULL || db->state.prepare == DNS_LOG_STATE_NOT_OK || 
     msg == NULL )
    {
      size = strlen(DNS_LOG_NO_DB_STR);
      *errorMsg = malloc(size*sizeof(char));

      strncpy(*errorMsg,DNS_LOG_NO_DB_STR,size);
      
      return DNS_LOG_NO_DB;
    }
  
  if(descFun == NULL)
    descFun = query_or_reply;
  

  /*
    Oops...Well, the dscFun dont seem to 
    have the possibility of using a extra argument..
    Have to check that later..
  */
    
  switch (descFun(NULL,msg))
    {
    case DNS_LOG_QUERY:
      ret = insert_q_msg(db,msg,funArg,errorMsg);
      
      if(ret == DNS_LOG_OK)
	{
	  ret=exec_sql_stmt(db->pre_stmt.q_stmt,errorMsg);
	}
      
      if(ret == DNS_LOG_OK)
	{
    
	  ret = reset_sql_stmt(db->pre_stmt.q_stmt,errorMsg);
	  //ret = clear_bindings_sql_stmt(db->pre_stmt.q_stmt,errorMsg);
	}


      
      //
      break;
    case DNS_LOG_REPLY:
      ret = insert_r_msg(db,msg,funArg,errorMsg);
	    
      if(ret == DNS_LOG_OK)
	{
	  ret=exec_sql_stmt(db->pre_stmt.r_stmt,errorMsg);
	}
      
      if(ret == DNS_LOG_OK)
	{
	  ret = reset_sql_stmt(db->pre_stmt.r_stmt,errorMsg);
	  //ret = clear_bindings_sql_stmt(db->pre_stmt.q_stmt,errorMsg);
	}




      //ret=insert_msg_reply(db,msg,funArg,errorMsg);
      break;
    case DNS_LOG_ERROR:
      fprintf(stderr," Message unknown or malformed...");
      ret = malformed_msg(errorMsg);
      break;
    default:
      fprintf(stderr," Message unknown or malformed...");
      ret = malformed_msg(errorMsg);
      break;
    }
	  

      return ret;
}


static void free_DNSLog_struct(DNSLog_struct *toFree)
{
  char *errorMsg;
  
  
  
  if(toFree->temp_file != NULL)
    {
      free(toFree->temp_file);
    }
  if(toFree->perm_file != NULL)
    {
      free(toFree->perm_file);
    }

  free(toFree->table_name.query);
  free(toFree->table_name.reply);
  free(toFree);
}



  

int DNSLog_close(void *db,char **errorMsg)
{
  int ret = DNS_LOG_OK;
  DNSLog_struct *db_struct = (DNSLog_struct *) db;

#ifdef _TIME_INDEX
  void *timer;
#endif

  
  if((ret=sqlite3_exec(db_struct->db,SQL_COMMAND_COMMIT,NULL,NULL,errorMsg)) != SQLITE_OK)
    {
      fprintf(stderr,"Unable to commit: %s\n",*errorMsg);
      return DNS_LOG_DB_ERROR;
    } 
  
  /*
    Testing timeing
  */
  
#ifdef _TIME_INDEX
  start_timer(&timer);
#endif
  
#ifdef SQL_COMMAND_CREATE_INDEX 
  if((ret=sqlite3_exec(db_struct->db,SQL_COMMAND_BEGIN_TR,NULL,NULL,errorMsg)) != SQLITE_OK)
    {
      fprintf(stderr,"Failed to start Transaction return code %d\n",ret);
      return DNS_LOG_DB_ERROR;
    }
  
  
  if((ret=createIndexers(db,errorMsg)) != DNS_LOG_OK)
    {
      return ret;
    }
  
  
  if((ret=sqlite3_exec(db_struct->db,SQL_COMMAND_COMMIT,NULL,NULL,errorMsg)) != SQLITE_OK)
    {
      fprintf(stderr,"Unable to commit: %s\n",*errorMsg);
      return DNS_LOG_DB_ERROR;
    } 
#endif

#ifdef _TIME_INDEX
  end_timer(timer);
#endif


  /*
    Need to finalize these before closing!! BUT IT DOES NOT WORK???
  */
  
   if(db_struct->pre_stmt.q_stmt != NULL)
     {
       if(finalize_sql_stmt(db_struct->pre_stmt.q_stmt,errorMsg) != DNS_LOG_OK)
       fprintf(stderr,"%s\n",errorMsg);
     }
   
   
  if(db_struct->pre_stmt.r_stmt != NULL)
    {
      if(finalize_sql_stmt(db_struct->pre_stmt.r_stmt,errorMsg) != DNS_LOG_OK)
      fprintf(stderr,"%s\n",errorMsg);
    }
  

    
  if(sqlite3_close(db_struct->db) != SQLITE_OK)
    {
      ret = DNS_LOG_DB_ERROR;
    }


  /* 
     IF temp file exists then take this and copy 
     to a permanent file.
     This is done in ram2disk.c
  */
  
  if(db_struct->temp_file != NULL)
    {
      if(cp_ram2disk(db_struct->temp_file,
			    db_struct->perm_file,
			    errorMsg)== RAM2DISK_ERROR)
	{
	  
	  ret = DNS_LOG_CP_RAM2DISK_ERROR;
	}
	
    }


  free_DNSLog_struct(db_struct);
  
  
  return ret;
}



int DNSLog_extra(void *db_struct,E1_fun *e1_fun,E2_fun *e2_fun,char **errorMsg)
{
  int ret = DNS_LOG_OK;
  DNSLog_struct *db = (DNSLog_struct *) db_struct;
  

  if(db == NULL || db->state.open == DNS_LOG_STATE_NOT_OK)
    {  
      *errorMsg = malloc(strlen(DNS_LOG_NO_DB_STR)*sizeof(char));
      strncpy(*errorMsg,DNS_LOG_NO_DB_STR,strlen(DNS_LOG_NO_DB_STR));
      return DNS_LOG_NO_DB;
    }
  
  
  /*
    Do not care if its NULL its that way anyway..
  */
  db->fun_e1 = e1_fun;
  db->fun_e2 = e2_fun;
  
  return ret;
}


