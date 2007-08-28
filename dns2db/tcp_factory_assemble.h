/* 
   $Id$
   

 */

#ifndef _TCP_FACTORY_ASSEMBLE
#define _TCP_FACTORY_ASSEMBLE

#include "dns2db.h"

#define SOCKET_STR "%s:%d"
#define SOCKET_STR_EXTRA_CHR 10	/* Count in length of port+:+\0 */

#define SOCKET_PAIR_STR "%s,%s" 
#define SOCKET_PAIR_STR_EXTRA_CHAR 2

#define TCP_FACTORY_ERROR -1
#define TCP_FACTORY_PART 0
#define TCP_FACTORY_FULL 1


char *get_socket_pair(const dns_package *);

int tcp_factory_assemble(const dns_package *,
			 int,
			 uint8_t *,
			 int,
			 uint8_t **);
void TCP_factory_init();
int tcp_factory_new_packet(const char *,int );
int tcp_factory_add_data(char *,
			 uint8_t *,
			 int ,
			 uint8_t **);
int tcp_factory_check_existens(char *);





#endif
