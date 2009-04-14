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
#include "list.h"
#include "tcp_seg.h"

typedef struct in6_addr in6addr_t;

typedef struct tcp_stream_t {
   in6addr_t *src_ip;
   in6addr_t *dst_ip;
   uint16_t src_port;
   uint16_t dst_port;
   list_t seg_list;
} tcp_stream_t;


/** Lookup a stream in the list of streams.
 */
tcp_stream_t *
tcp_lookup (
   in6addr_t *src_ip, //!< In: IPv6 address in presentation format.
   in6addr_t *dst_ip, //!< In: IPv6 address in presentation format.
   uint16_t src_port, //!< Port number.
   uint16_t dst_port //!< Port number. 
);


/** Add a segment to a stream.
 */
void
tcp_add_segment (
   tcp_stream_t *st, //!< In: Stream.
   libtrace_tcp_t *tcp, //!< In: TCP segment.
   uint32_t *rest //!< In: number of bytes in TCP segment (= rest after IP header).
);


/** Add a new stream to the list of streams.
 */
tcp_stream_t *
tcp_add_stream (
   in6addr_t *src_ip, //!< In: IPv6 address in presentation format.
   in6addr_t *dst_ip, //!< In: IPv6 address in presentation format.
   uint16_t src_port, //!< Port number.
   uint16_t dst_port //!< Port number.
);


/** Get the total payload from the stream.
 */
uint8_t *
tcp_get_stream_data (
   tcp_stream_t *st, //!< Stream.
   uint32_t *rest //!< Out: number of bytes of data.
);


/** Free all allocated memory for the stream and destroy the stream.
 */
void
tcp_delete_stream (
   tcp_stream_t *st //!< In: stream.
);


/** Add segment to a stream.
 */
list_t
tcp_add_to_stream (
   in6addr_t *src_ip, //!< In: IPv6 address in presentation format.
   in6addr_t *dst_ip, //!< In: IPv6 address in presentation format.
   libtrace_tcp_t *tcp, //!< In: TCP segment.
   uint32_t *rest //!< In: number of bytes in TCP segment (= rest after IP header).
);
#endif

