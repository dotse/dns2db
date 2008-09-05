/*
  $Id: arg_handle.h,v 1.3 2007/05/07 07:14:51 calle Exp $
*/

#ifndef READ_PCAP_ARG_HANDLE_H
#define READ_PCAP_ARG_HANDLE_H


typedef struct
{
  char *type;
  unsigned int qo:1;
  unsigned int ro:1;
  unsigned int overwrite:1;
  
  char *database;
  char *q_table;
  char *r_table;
  char *q_regexp;
  char *src_regexp;

  char *bpf;
  char **pcap_files;
  int nr_files;
} arg_struct;


arg_struct *check_options(int argc,char** argv);
#endif
