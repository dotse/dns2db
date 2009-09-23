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

#ifndef TCP_H
#define TCP_H

#include <stdio.h>
#include <netinet/in.h>
#include "libtrace.h"
#include "global.h"

typedef struct in6_addr in6addr_t;



/** Assembles tcp packets into streams and returns data 
    when 'fin' has been recieved
 */
uint8_t *
assemble_tcp (
  in6addr_t *src_ip, 
  in6addr_t *dst_ip, 
   uint16_t src_port,
   uint16_t dst_port,
   uint32_t *rest,
   uint32_t seq,
   uint8_t *data, 
   size_t len,
   char syn,
   char fin,
   char rst,
   char ack
);

#endif

