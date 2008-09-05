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
#include "dns2sqlite.h"

static sqlite3 *G_DB;

// === Local function prototypes ===============================================
void
usage (char *argv0);

char *
sec_to_datetime_str (long s);

char *
make_dt_filename (char *dt, char *filename);

char *
make_db_dir_name (char *fn);

char *
make_full_db_path (char *folder, char *db_dir_name);

unsigned long
interval_start (unsigned long secs, unsigned long interval);

// === Function implementations ================================================

// --- sec_to_datetime_str -----------------------------------------------------
char *
sec_to_datetime_str (long s) {
   char *dt = (char *) calloc (1, strlen ("YYYYMMDDHHMISS") + 1);
   if (dt == NULL) {
      return NULL;
   }

   if (strftime (dt, 15, "%Y%m%d%H%M", gmtime (&s))) {
      return dt;
   }
   else {
      XFREE(dt);
      return NULL;
   }
}


// --- make_dt_filename --------------------------------------------------------
char *
make_dt_filename (char *dt, char *filename) {
   int fn_len = strlen (filename);
   int dt_len = strlen (dt);
   int dt_flen = fn_len + dt_len;

   char *dt_f = (char *) calloc (1, dt_flen + 1);
   if (dt_f == NULL) {
      return NULL;
   }
   
   strncpy (dt_f, filename, fn_len);
   strncpy (dt_f + fn_len, dt, dt_len);
   dt_f [dt_flen + 1] = '\0';
   return dt_f;
}

// --- make_db_dir -------------------------------------------------------------
char *
make_db_dir_name (char *fn) {
   const unsigned char d_len = strlen ("YYYYMMDD");
   char *d = (char *) calloc (1, d_len + 1);
   if (d == NULL) {
      return NULL;
   }

   strncpy (d, fn, d_len);
   return d;
}

// --- make_full_db_path -------------------------------------------------------
char *
make_full_db_path (char *folder, char *db_dir_name) {
   unsigned int f_len = strlen (folder);
   unsigned int d_len = strlen (db_dir_name);
   
   char *full_path = (char *) calloc (1, f_len + d_len + 1);
   if (full_path == NULL) {
      return NULL;
   }
   
   char *c;
   for (c = folder; *(c + 1) != '\0'; c++);

   strncpy (full_path, folder, f_len);
   if (*c != '/') {
      strncpy (full_path + f_len++, "/", 1);
   }
   strncpy (full_path + f_len, db_dir_name, d_len);
   full_path [f_len + d_len + 1] = '\0';
   return full_path;
}

// --- partition_start ---------------------------------------------------------
// split a day into intervals of size "interval" seconds and return the start
// of the interval, counted from the Unix epoch, in which "secs" occur.
// N.B. interger arithmetic being used! 
unsigned long
interval_start (unsigned long secs, unsigned long interval) {
   const unsigned int secs_in_day = 86400;
   const unsigned int secs_into_day = secs % secs_in_day;
   const unsigned int interval_into_day = secs_into_day / interval;
   const unsigned int delta = (secs_into_day - interval_into_day * interval);
   return secs - delta;
}

// --- usage -------------------------------------------------------------------
void
usage (char *argv0) {
   fprintf (stderr, "usage: %s [options]\n", argv0);
   for (unsigned int i = 0; i < NUM_OPTS; ++i) {
      fprintf (stderr, "%s\n", G_OPTS [i]);
   }
}


// --- main --------------------------------------------------------------------
int 
main (int argc, char *argv []) {
   FILE *fp = NULL;
   sql_stmt_t *stmts = NULL;
   trace_t *t = NULL;
   bool_t only_q = FALSE;
   bool_t only_r = FALSE;
   bool_t dbf_overwrite = FALSE;
   char *filename = NULL;
   char *template = NULL;
   char *folder = ".";
   char *db_dir_name = NULL;
   char *dt_filename = NULL;
   unsigned long partition_interval = PARTITION_INTERVAL_SECS;
   unsigned long partition_start = 0;
   int packet_count = 0;
   int opt_idx = 0;
   int c = 0;
   int rc = 0;
   
   // command line option parsing
   struct option long_opts [] = {
      {"help", no_argument, NULL, 'h'},
      {"version", no_argument, NULL, 'v'},
      {"template", required_argument, NULL, 't'},
      {"queries_only", no_argument, NULL, 'q'},
      {"replies_only", no_argument, NULL, 'r'},
      {"database", required_argument, NULL, 'd'},
      {"db_overwrite", no_argument, NULL, 'o'},
      {"interval", required_argument, NULL, 'i'},
      {"db_folder", required_argument, NULL, 'f'},
      { NULL, 0, NULL, 0 }
   };

   while ((c = getopt_long (argc, argv, "hvt:qrd:n:oi:f:", long_opts, &opt_idx)) != -1) {
      switch (c) {
         case 'v':
            fprintf (stdout, "%s\n", VERSION); // VERSION defined in global.h
            exit (0);
            break;
         case 't':
            template = optarg;
            break;
         case 'q':
            only_q = TRUE;
            break;
         case 'r':
            only_r = TRUE;
            break;
         case 'd':
            filename = optarg;
            break;
         case 'o':
            dbf_overwrite = TRUE;
            break;
         case 'i':
            partition_interval = strtoul (optarg, NULL, NUM_BASE);
            partition_interval = (partition_interval < 1 ? 1 : partition_interval) * 60;
            break;
         case 'f':
            folder = optarg;
            break;
         default:
            fprintf (stderr, "Unknown option: %c\n", c);
            // FALL THRU
         case 'h':
            usage (argv [0]);
            return 0;
      }
   }
   argc -= optind;
   argv += optind;

   // handle dangling command line arguments
   switch (argc) {
      case 0:
         fp = stdin;
         break;
      case 1:
         fp = fopen (argv [argc -1], "r");
         if (fp == NULL) {
            perror (argv [argc -1]);
            return 1;
         }
         break;
      default:
         usage (argv [0]);
         return 1;
   }

   // main loop   
   while ((t = parse_line (fp)) != NULL) {
      partition_start = partition_start == 0
                          ? interval_start (t->s, partition_interval)
                          : partition_start;
      if ((unsigned long) t->s >= (partition_start + partition_interval)) {
         rc = commit ((stmts + COMMIT)->pstmt);
         close_db (G_DB);
         G_DB = NULL;
         rc = chdir ("..");
         if (rc == -1) {
            perror (NULL);
            XFREE(db_dir_name);
            return FAILURE;
         }
         XFREE(db_dir_name);
         partition_start += partition_interval;
      }
      
      // check if db_dir_name is set. If not, set the filename and the db_dir_name.
      // should this be done here or after "if (!isdbopen ...)" below?
      if (db_dir_name == NULL) {
         char *dt;
         char *full_path;
         
         dt = sec_to_datetime_str (partition_start);
         if (dt == NULL) {
            return FAILURE;
         }

         dt_filename = make_dt_filename (dt, filename);
         if (dt_filename == NULL) {
            XFREE(dt);
            return FAILURE;
         }
         
         db_dir_name = make_db_dir_name (dt);
         if (db_dir_name == NULL) {
            XFREE(dt);
            XFREE(dt_filename);
            return FAILURE;
         }

         full_path = make_full_db_path (folder, db_dir_name);
         if (full_path == NULL) {
            XFREE(dt);
            XFREE(dt_filename);
            XFREE(db_dir_name);
            return FAILURE;
         }
         
         // only need to create dir when it does not exist! Add check for that
         // or try to create and handle the error if it exists.
         rc = mkdir (full_path, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
         if (rc == -1 && errno != EEXIST) {
            perror (NULL);
            XFREE(dt);
            XFREE(dt_filename);
            XFREE(db_dir_name);
            XFREE(full_path);
            return FAILURE;
         }
         rc = chdir (full_path);
         if (rc == -1) {
            perror (NULL);
            XFREE(dt);
            XFREE(dt_filename);
            XFREE(db_dir_name);
            XFREE(full_path);
            return FAILURE;
         }
         XFREE(full_path);
      }
      
      if (!isdbopen (G_DB)) {
         if (!open_db (filename, &G_DB)) {
            if (!create_db (template, dt_filename, dbf_overwrite, &G_DB)) {
               fprintf (stderr, "Failed to create new db.\n");
               XFREE(dt_filename); 
               exit (1);
            }
            XFREE(dt_filename);
         }
         if (!prepare_stmts (G_DB, &stmts)) {
            fprintf (stderr, "Failed to prepare sql statements.\n");
            close_db (G_DB);
            exit (1);
         }
         rc = start_transaction ((stmts + BEGIN_TRANS)->pstmt);
      }
      
      if (!store_to_db (G_DB, stmts, t)) {
         fprintf (stderr, "Failed to store data to db.\n");
      }

      trace_free (t);
      packet_count++;
   }

   // clean up before exit
   fclose (fp);
   rc = commit ((stmts + COMMIT)->pstmt);
   close_db (G_DB);
   exit (0);
}
