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

#include "trace_data.h"

trace_t *
make_trace () {
   trace_t *t = (trace_t *) calloc (1, sizeof (trace_t));
   assert (t != NULL);
   return t;
}

void
trace_free (trace_t *t) {
   if (t->src_addr != NULL) XFREE(t->src_addr);
   if (t->dst_addr != NULL) XFREE(t->dst_addr);
   if (t->data != NULL) XFREE(t->data);
   XFREE(t);
}

unsigned long
trace_get_seconds (trace_t *t) {
   return t->s;
}

unsigned long
trace_get_micro_seconds (trace_t *t) {
   return t->us;
}

uint16_t
trace_get_ethertype (trace_t *t) {
   return t->ethertype;
}

char *
trace_get_src_addr (trace_t *t) {
   return t->src_addr;
}

char *
trace_get_dst_addr (trace_t *t) {
   return t->dst_addr;
}

uint16_t
trace_get_port (trace_t *t) {
   return t->port;
}

uint8_t
trace_get_protocol (trace_t *t) {
   return t->proto;
}

uint8_t *
trace_get_data (trace_t *t) {
   return t->data;
}

unsigned long
trace_get_length (trace_t *t) {
   return t->len;
}

void
trace_set_seconds (trace_t *t, unsigned long s) {
   t->s = s;
}

void
trace_set_micro_seconds (trace_t *t, unsigned long us) {
   t->us = us;
}

void
trace_set_ethertype (trace_t *t, unsigned short e) {
   t->ethertype = e;
}

void
trace_set_src_addr (trace_t *t, char *s) {
   t->src_addr = s;
}

void
trace_set_dst_addr (trace_t *t, char *d) {
   t->dst_addr = d;
}

void 
trace_set_port (trace_t *t, unsigned short p) {
   t->port = p;
}

void
trace_set_protocol (trace_t *t, unsigned short p) {
   t->proto = p;
}

void
trace_set_data (trace_t *t, uint8_t *d) {
   t->data = d;
}

void
trace_set_length (trace_t *t, unsigned int n) {
   t->len = n;
}
