/*
  $Id: SQLCommands.h,v 1.2 2007/04/12 09:11:03 calle Exp $

  Copyright(c) 2007 by Carl Olsen
  
  

*/
#include "config.h"
#ifndef SQL_COMMANDS
#define SQL_COMMANDS


#define SQL_COMMAND_CREATE_Q_TABLE "create table %s(id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER,msg_id INTEGER,Client_num INTEGER,Client TEXT,Src_port INTEGER,Qtype INTEGER,Qclass INTEGER,MsgLen INTEGER,Qname TEXT,Opcode INTEGER,Rd INTEGER,Opt_RR INTEGER,Do INTEGER,Version TEXT,E1 TEXT,E2 TEXT);"


#define SQL_COMMAND_CREATE_R_TABLE "create table %s(id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER,msg_id INTEGER,Client_num INTEGER,Client TEXT,Src_port INTEGER,Qtype INTEGER,Qclass INTEGER,MsgLen INTEGER,Qname TEXT,Opcode INTEGER,Rcode INTEGER,Rd INTEGER,Opt_RR INTEGER,Do INTEGER,Version TEXT,E1 TEXT,E2 TEXT);"

#define SQL_COMMAND_QUERY_INSERT "insert into %s(ts,msg_id,Client_num,Client,Src_port,Qtype,Qclass,MsgLen,Qname,Opcode,Rd,Opt_RR,Do,Version,E1,E2) VALUES ( %d,%d,%d,\"%s\",%d,%d,%d,%d,\"%s\",%d,%d,%d,%d,%d,\"%s\",\"%s\");"

#define SQL_COMMAND_REPLY_INSERT "insert into %s(ts,msg_id,Client_num,Client,Src_port,Qtype,Qclass,MsgLen,Qname,Opcode,Rcode,Rd,Opt_RR,Do,Version,E1,E2) VALUES ( %d,%d,%d,\"%s\",%d,%d,%d,%d,\"%s\",%d,%d,%d,%d,%d,%d,\"%s\",\"%s\");"





/*
  The next part is a couple of index.
  These should be put in as options, 
  but for now they are not..
*/


#define SQL_COMMAND_ID_INDEX "create unique index index_id on Q (id);"

#define SQL_COMMAND_CLIENT_INDEX "create index index_Client on Q (Client);"

#define SQL_COMMAND_QNAME_INDEX "create index index_Qname on Q (Qname);"

#define SQL_COMMAND_E1_INDEX "create index index_E1 on Q (E1);"
#define SQL_COMMAND_E2_INDEX "create index index_E2 on Q (E2);"
#define SQL_COMMAND_CLIENT_E1_INDEX "create index index_Client_E1 on Q(Client, E1);"
#define SQL_COMMAND_CLIENT_QNAME_INDEX "create index index_Client_Qname on Q (Client, Qname);"
#define SQL_COMMAND_E1_E2_INDEX "create index index_E1_E2 on Q (E1, E2);"




//#define SQL_COMMAND_CREATE_INDEX 



#define SQL_COMMAND_BEGIN_TR "BEGIN TRANSACTION;"
#define SQL_COMMAND_COMMIT "COMMIT;"
#define SQL_ASYN_PRAGMA "PRAGMA synchronous = OFF;PRAGMA temp_store=2;pragma default_cache_size =65536;pragma cache_size = 8192;"

#endif
