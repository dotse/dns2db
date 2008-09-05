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
#ifndef LINE_PARSER_H
#define LINE_PARSER_H

#include <ctype.h>
#include "global.h"

typedef enum State {
   ERR, SECS, USECS, ETHERTYPE, SRC, DST, PORT, PROTO, LEN, DATA, DONE
} State;

typedef enum Constant {EOS = 0, RS = 10, FS = ','} Constant;

/** Parse a single csv-line of network data. The line should have the following
 * format:
 * <ulong>,<ulong>,<uint16_t>,<IPv6-address>,<IPv6-address>,<uint16>,<uint8_t>,<ulong>,<hex>\n
 * where <ulong> is an unsigned long in decimal, <uint16_t> is an unsigned 16-bit
 * integer in decimal, <uint8_t> is an unsigned 8-bit integer in decimal, 
 * <IPv6-address> is an IPv6 address in presentation format, and <hex> is a 
 * sequence of hexadecimal digits where each pair represent one byte of data. 
 */
trace_t *
parse_line (
   FILE *fp //!< An open file pointer.
);

#endif
