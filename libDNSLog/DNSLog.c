/*
  $Id: DNSLog.c,v 1.3 2007/04/24 15:42:28 calle Exp $

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
} DNSLog_struct;



static void free_DNSLog_struct(DNSLog_struct *toFree)
{
  
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


static char *get_ipv4_addr(const dns_message *msg)
{
  char *ipv4_ascii = NULL;
  int size =0;
    /*
    The string is returned in a statically allocated buffer,  which  subse‐
    quent calls will overwrite. (inet_ntoa)
    This means we need to copy the result to another string,
    so the filter does not change it..
  */
  char *temp_addr = inet_ntoa(msg->client_ipv4_addr);
  if(temp_addr != NULL)
    {
      size = strlen(temp_addr)+1;
      ipv4_ascii = malloc(size*sizeof(char));
      
      strncpy(ipv4_ascii,temp_addr,size);
      
    }
  
  return ipv4_ascii;
}

//--------------------
/*
  Inserts the dns_message to the database..
  These two functions are very similair, and maybe we can break them up
  to make smaller...but not now..
*/

static int insert_msg_query(DNSLog_struct *db,dns_message *msg,void *funArg,char **errorMsg)
{
  int ret =DNS_LOG_INTERNAL_ERROR;
  char *e1=NULL;
  char *e2=NULL;
  char *ipv4_ascii = get_ipv4_addr(msg);
  char sql_cmd[SQL_CMD_SZ]; // only temp...

  
  
  
    

  
  if(db->fun_e1 != NULL )
    {
      e1 = db->fun_e1(msg,funArg);
    }

  
  if(db->fun_e2 != NULL )
    {
      e2 = db->fun_e2(msg,funArg);
    }
  
  
  snprintf(sql_cmd,SQL_CMD_SZ,SQL_COMMAND_QUERY_INSERT,
	   db->table_name.query,
	   (int)msg->ts.tv_sec, 
	   msg->msg_id,
	   msg->client_ipv4_addr.s_addr,
	   ipv4_ascii,
	   msg->src_port,
	   msg->qtype,
	   msg->qclass,
	   msg->msglen,
	   msg->qname,
	   msg->opcode,
	   msg->rd,
	   msg->edns.found,
	   msg->edns.DO,
	   msg->edns.version,
	   e1,
	   e2);
  
  
  
  
  /*
    So we finally made it to this point time to insert the message into the database..

  */
  
  ret=sqlite3_exec(db->db,sql_cmd,NULL,NULL,errorMsg);
  if(ret != SQLITE_OK)
    {
      fprintf(stderr,"ERROR could not open file %s %d\n",*errorMsg,ret);
    }
  else
    ret = DNS_LOG_OK;
  
  if(e1 != NULL)
    free(e1);
  if(e2 != NULL)
    free(e2);

  free(ipv4_ascii);
    
  return ret;
  


}


static int insert_msg_reply(DNSLog_struct *db,dns_message *msg,void *funArg,char **errorMsg)
{

  char *e1 =NULL;
  char *e2 = NULL;
  int ret =DNS_LOG_INTERNAL_ERROR;

  char sql_cmd[SQL_CMD_SZ]; // only temp...Used in this context...
  char *ipv4_ascii = get_ipv4_addr(msg);

  if(db->fun_e1 != NULL )
    {
      e1 = db->fun_e1(msg,funArg);
    }
 
  if(db->fun_e2 != NULL )
    {
      e2 = db->fun_e2(msg,funArg);
    }

    

  
  snprintf(sql_cmd,SQL_CMD_SZ,SQL_COMMAND_REPLY_INSERT,
	   db->table_name.reply,
	   (int)msg->ts.tv_sec, 
	   msg->msg_id,
	   msg->client_ipv4_addr.s_addr,
	   ipv4_ascii,
	   msg->src_port,
	   msg->qtype,
	   msg->qclass,
	   msg->msglen,
	   msg->qname,
	   msg->opcode,
	   msg->rcode,
	   msg->rd,
	   msg->edns.found,
	   msg->edns.DO,
	   msg->edns.version,
	   e1,
	   e2);
  
  //printf("%s\n",sql_cmd);

  /*
    So we finally made it to this point time to insert the message into the database..
  */
  
  ret=sqlite3_exec(db->db,sql_cmd,NULL,NULL,errorMsg);
  if(ret != SQLITE_OK)
    {
      fprintf(stderr,"ERROR could not open file %s %d\n",*errorMsg,ret);
    }
    else
      ret = DNS_LOG_OK;

  if(e1!=NULL)
    free(e1);
  if(e2 != NULL)
    free(e2);
  
  free(ipv4_ascii);
  return ret;
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
      ret=insert_msg_query(db,msg,funArg,errorMsg);
      break;
    case DNS_LOG_REPLY:
      ret=insert_msg_reply(db,msg,funArg,errorMsg);
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


