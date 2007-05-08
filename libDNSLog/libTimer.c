
/*
  $Id: libTimer.c,v 1.1 2007/04/11 15:02:42 calle Exp $

*/
#include "config.h"
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>




typedef struct {
  struct timeval *exec_start;
  struct timeval *exec_end;
} timer_struct;



void start_timer(void **in)
{
  timer_struct *timer = malloc(sizeof(timer_struct));
  struct timeval *start = malloc(sizeof(*start));
  struct timeval *end = malloc(sizeof(*end));
  
  timerclear(start);
  timerclear(end);
  if(gettimeofday(start,NULL) == 0)
    {
      timer->exec_start = start;
      timer->exec_end = end;
      *in = (void *) timer;
    }
  else
    {
      perror(NULL);
    }
}
  

void end_timer(void *in)
{
  
  timer_struct *tm_struct = (timer_struct *) in;
  struct timeval *start = tm_struct->exec_start;
  struct timeval *end = tm_struct->exec_end;
  
  if(gettimeofday(end,NULL) != 0)
    {
      perror(NULL);
    }
  
  fprintf(stderr,"Sec: %d usec %d \n",end->tv_sec-start->tv_sec,end->tv_usec-start->tv_usec);
  
  free(start);
  free(end);
  free(tm_struct);
}
    



