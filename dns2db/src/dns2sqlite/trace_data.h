/*! \file */ 
/*
 * Copyright (c) 2007 .SE (The Internet Infrastructure Foundation).
 *                  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ##################################################################### 
 *
 */
#ifndef TRACE_DATA_H
#define TRACE_DATA_H

#include "global.h"

struct trace_data {
   long s;
   long us;
   uint16_t ethertype;
   char *src_addr;
   char *dst_addr;
   uint16_t port;
   uint8_t proto;
   uint8_t *data;
   unsigned long len;
};

typedef struct trace_data trace_t;

trace_t *
make_trace (void);

void
trace_free (trace_t *t);

unsigned long
trace_get_seconds (trace_t *t);

unsigned long
trace_get_micro_seconds (trace_t *t);

uint16_t
trace_get_ethertype (trace_t *t);

char *
trace_get_src_addr (trace_t *t);

char *
trace_get_dst_addr (trace_t *t);

uint16_t
trace_get_port (trace_t *t);

uint8_t
trace_get_protocol (trace_t *t);

uint8_t *
trace_get_data (trace_t *t);

unsigned long
trace_get_length (trace_t *t);

void
trace_set_seconds (trace_t *t, unsigned long s);

void
trace_set_micro_seconds (trace_t *t, unsigned long us);

void
trace_set_ethertype (trace_t *t, unsigned short e);

void
trace_set_src_addr (trace_t *t, char *s);

void
trace_set_dst_addr (trace_t *t, char *d);

void 
trace_set_port (trace_t *t, unsigned short p);

void
trace_set_protocol (trace_t *t, unsigned short p);

void
trace_set_data (trace_t *t, uint8_t *d);

void
trace_set_length (trace_t *t, unsigned int n);

#endif
