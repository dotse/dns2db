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
#ifndef DNS2SQLITE_H
#define DNS2SQLITE_H

#include <getopt.h>
#include <limits.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include "global.h"
#include "db.h"
#include "line_parser.h"


#define DNS2SQLITE_VERSION "DNS2SQLITE "VERSION
#define PARTITION_INTERVAL_SECS 900L;
#define NUM_BASE 10

static char *G_OPTS [] = { 
   "--help | -h             shows this help", 
   "--version | -v          show dns2sqlite version", 
   "--show_schema | -s      shows the queries that generate the sql tables",  
   "--queries_only | -q     only log dns queries",
   "--replies_only | -r     only log dns replies", 
   "--database | -d dbf     database filename", 
   "--append | -a           append to existing databasefiles",  
   "--db_overwrite | -o     overwrite existing databasefiles", 
   "--interval | -i min     split interval",
   "--db_folder | -f dir    database folder"
};

#define NUM_OPTS (sizeof (G_OPTS) / sizeof (G_OPTS [0]))

#endif

