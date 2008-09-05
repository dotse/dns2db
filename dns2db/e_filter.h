/*
  $Id: e_filter.h,v 1.3 2007/05/05 16:50:05 calle Exp $
*/

#ifndef E_FILTER_H
#define E_FILTER_H

#define E_FILTER_USE_DEFAULT 1

#define E_FILTER_OK 0
#define E_FILTER_INTERNAL_ERROR -1

#define E_FILTER_REGEXP_COMP_ERROR -2
#define E_FILTER_REGEXP_COMP_ERROR_STR "Error while compiling regexp"

#define E_FILTER_NO_REGEXP -3
#define E_FILTER_NO_REGEXP_STR "No regexp was compiled!"

#define E_FILTER_MEM_ALLOC_ERR -4
#define E_FILTER_MEM_ALLOC_ERR_STR "Memory allocation problem while compiling regexp"


/*
  Exported functions..
*/
int e2_filter_compile(char *,char **);
void *e2_filter_function(char **);


int e1_filter_compile(char *,char **);
void *e1_filter_function(char **);

void e_filter_free(void);


#endif
