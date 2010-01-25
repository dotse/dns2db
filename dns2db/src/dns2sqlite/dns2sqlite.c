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
#include "dns2sqlite.h"

static sqlite3 *G_DB = NULL;

/** Log function comaptible to syslog()
 */
void    d2log(int fp, const char *fmt, ...)
{
    char *str,*strp;
    char string[1024];
    va_list ap;

    va_start(ap,fmt);
    vsnprintf(string,sizeof(string),fmt,ap);
    va_end(ap);


    syslog(fp,"%s",string);
    fprintf(stderr,"%s\n",string);

}


// === Local function prototypes ===============================================
/** Print command line usage string.
 */
void
usage (
   char *argv0 //!< argv [0].
);

/** Convert seconds since the Unix epoch to a YYYYMMDDHHMI-string.
 */
char *
sec_to_datetime_str (
   unsigned long s //!< Seconds since Unix epoch.
);

/** Append a datetime string to a filename.
 */
char *
make_dt_filename (
   char *dt, //!< A datetime string (as returned from sec_to_datetime_str()).
   char *filename //!< A filename as a string.
);

/** Make a string representing a directory name from a datetime string.
 */
char *
make_db_dir_name (
   char *dt //!< A datetime string (as returned from sec_to_datetime_str())
);

/** Make a string representing the full path to a directory for database files.
 */
char *
make_full_db_path (
   char *folder, //!< Complete path to base directory.
   char *db_dir_name //!< Subdir within the base directory.
);

/** Split a day into intervals of size "interval" seconds and return the start
 * of the interval, counted from the Unix epoch, in which "secs" occur.
 */
unsigned long
interval_start (
   unsigned long secs, //!< Seconds since Unix epoch.
   unsigned long interval //!< Interval size in seconds.
);

/** Start of the next database "partition".
 */
unsigned long
p_start (
   unsigned long ps, //!< Previous partition start time (in seconds of the day).
   unsigned long s, //!< Seconds since the Unix epoch.
   unsigned long pi //!< Partition interval size in seconds.
);

/** Create a directory.
 */
int
make_db_dir (
   char *dt, //!< A datetime string (as returned by sec_to_datetime_str).
   char *dir //!< String representing the complete path to a base directory. 
);

// === Function implementations ================================================

// --- sec_to_datetime_str -----------------------------------------------------
char *
sec_to_datetime_str (unsigned long s) {
   const unsigned short dt_len = strlen ("YYYYMMDDHHMI") + 1;
   const time_t t = s; //N.B. time_t may be int or real. Use conversion, not casting!
   char *dt = (char *) calloc (1, dt_len);
   if (dt == NULL) {
      return NULL;
   }

   if (strftime (dt, dt_len, "%Y%m%d%H%M", gmtime (&t))) {
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
   if (dt == NULL || filename == NULL)
      return NULL;
	
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

// --- make_db_dir_name---------------------------------------------------------
char *
make_db_dir_name (char *dt) {
   const unsigned char d_len = strlen ("YYYYMMDD");
   char *d = (char *) calloc (1, d_len + 1);
   if (d == NULL) {
      return NULL;
   }

   strncpy (d, dt, d_len);
   return d;
}

// --- make_full_db_path -------------------------------------------------------
char *
make_full_db_path (char *folder, char *db_dir_name) {
   unsigned int f_len = strlen (folder);
   unsigned int d_len = strlen (db_dir_name);
   
   char *full_path = (char *) calloc (1, f_len + d_len + 2);
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

// --- interval_start ---------------------------------------------------------
// N.B. interger arithmetic being used! 
unsigned long
interval_start (unsigned long secs, unsigned long interval) {
   const unsigned int secs_in_day = 86400;
   const unsigned int secs_into_day = secs % secs_in_day;
   const unsigned int interval_into_day = secs_into_day / interval;
   const unsigned int delta = (secs_into_day - interval_into_day * interval);
   return secs - delta;
}

// --- p_start -----------------------------------------------------------------
unsigned long
p_start (unsigned long ps, unsigned long s, unsigned long pi) {
   return ps == 0 ? interval_start (s, pi) : ps;
}

// --- make_db_dir -------------------------------------------------------------
int
make_db_dir (char *dt, char *dir) {
   char *db_dir_name = NULL;
   char *full_path = NULL;
   int rc = 0;
  
   db_dir_name = make_db_dir_name (dt);
   if (db_dir_name == NULL) {
      return FAILURE;
   }
   
   full_path = make_full_db_path (dir, db_dir_name);
   XFREE(db_dir_name);
   if (full_path == NULL) {
      return FAILURE;
   }

   rc = mkdir (full_path, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
   if (rc == -1 && errno != EEXIST) {
      perror (NULL);
      XFREE(full_path);
      return FAILURE;
   }
   rc = chdir (full_path);
   if (rc == -1) {
      perror (NULL);
      XFREE(full_path);
      return FAILURE;
   }
   XFREE(full_path);
   return SUCCESS;
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
mainloop (int argc, char *argv []) {
    FILE *fp = NULL;
    FILE *tempfp = NULL;
    sql_stmt_t *stmts = NULL;
    trace_t *t = NULL;
    bool_t only_q = FALSE;
    bool_t append = FALSE;
    bool_t only_r = FALSE;
    bool_t dbf_overwrite = FALSE;
    char *filename = NULL;
    char *folder = ".";
    char *dt = NULL;
    char *dt_filename = NULL;
    unsigned long partition_interval = PARTITION_INTERVAL_SECS;
    unsigned long partition_start = 0;
    int opt_idx = 0;
    int c = 0;
    int rc = 0;

    // command line option parsing
    struct option long_opts [] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {"append", no_argument, NULL, 'a'},
        {"show_schema", no_argument, NULL, 's'},
        {"queries_only", no_argument, NULL, 'q'},
        {"replies_only", no_argument, NULL, 'r'},
        {"database", required_argument, NULL, 'd'},
        {"db_overwrite", no_argument, NULL, 'o'},
        {"interval", required_argument, NULL, 'i'},
        {"db_folder", required_argument, NULL, 'f'},
        { NULL, 0, NULL, 0 }
    };


    while ((c = getopt_long (argc, argv, "hvasqrd:n:oi:f:", long_opts, &opt_idx)) != -1) {
        switch (c) {
            case 'v':
            fprintf (stdout, "%s\n", DNS2SQLITE_VERSION); // VERSION defined in dns2sqlite.h
            exit (0);
            break;
            case 's':
            fprintf (stdout, "%s\n", g_tabledefs); // VERSION defined in dns2sqlite.h
            exit (0);
            break;
            case 'a':
            append = TRUE;
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
    // N.B. this does not work if a pipe and a file is used at the same time.
    // If files are given then they should be processed before the pipe is read
    // from stdin. That is, while argc > 0 open each file and go to the main
    // loop. When argc = 0 then open stdin and go to the main loop:
    //
    // while (argc > 0) {
    //    fp = fopen (argv [argc -1], "r");
    //    if (fp == NULL) {return FAILURE}
    //    else {read_file (fp, ...);}
    //    fclose (fp);
    //    argc--;
    // }
    // fp = stdin;

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

    if (filename == NULL) {
        fprintf (stderr, "Error: No database specified \n");
    }
   

    // main loop
    // This should at least be moved into its own function.
    while ((t = parse_line (fp)) != NULL) {
        partition_start = p_start (partition_start, t->s, partition_interval);

        if ((unsigned long) t->s >= (partition_start + partition_interval)) {
            rc = commit ((stmts + COMMIT)->pstmt);
            close_db (G_DB);
            G_DB = NULL;
            rc = chdir ("..");
            if (rc == -1) {
            perror (NULL);
            return FAILURE;
            }
            partition_start += partition_interval;
        }
        // check if database is open
        if (!isdbopen (G_DB)) {
          
            // create directory name
            if (dt)
                XFREE(dt);
            dt = sec_to_datetime_str (partition_start);
            if (!dt) 
                return FAILURE;
            
            // generate path 
            if (dt_filename)
                XFREE(dt_filename);
            dt_filename = make_dt_filename (dt, filename);
            if (dt_filename == NULL) {
                XFREE(dt);
                return FAILURE;
            }

            // create directory
            if (make_db_dir (dt, folder) != SUCCESS) {
                XFREE(dt);
                XFREE(dt_filename);
                return FAILURE;
            }
            XFREE(dt);

            if (dbf_overwrite)
            {
                rc = unlink(dt_filename);
                if (rc==0)
                    d2log (LOG_ERR|LOG_USER, "Unlinked file %s (due to overwrite flag).",dt_filename);
                else
                {
                    rc = errno;
                    if (rc != ENOENT)
                    {
                        d2log (LOG_ERR|LOG_USER, "Failed to unlink %s (overwrite) file code %d.",dt_filename,rc);
                        XFREE(dt);
                        XFREE(dt_filename);
                        return FAILURE;
                    }
                }
            }
            else
            {
                if (append == FALSE)
                {
                    // simplistic test whether the database file exists
                    tempfp = fopen (dt_filename, "r");
                    if (tempfp) {
                        d2log (LOG_ERR|LOG_USER, "Error: Database file %s exists ! ( use -a to append or -o owerwrite ).",dt_filename);
                        fclose (tempfp);
                        return FAILURE;
                    }
                }
            }
            
            if (!open_db (dt_filename, &G_DB, append)) {
                d2log (LOG_ERR|LOG_USER, "Failed to create new db %s.",dt_filename);
                XFREE(dt_filename);
                return FAILURE;
            }
  
            if (!prepare_stmts (G_DB, &stmts)) {
                d2log (LOG_ERR|LOG_USER, "Failed to prepare sql statements for db: %s.",dt_filename);
                close_db (G_DB);
                return FAILURE;
            }
            rc = start_transaction ((stmts + BEGIN_TRANS)->pstmt);
        }

        if (!store_to_db (G_DB, stmts, t, only_q, only_r)) {
            d2log (LOG_ERR|LOG_USER, "Failed to store data to db.\n");
        }

        trace_free (t);
    }

    // clean up before exit
    fclose (fp);
    rc = commit ((stmts + COMMIT)->pstmt);
    close_db (G_DB);
}


int 
main (int argc, char *argv []) {

   openlog("dns2sqlite",LOG_PID,LOG_USER);  // open d2log
//   d2log (LOG_ERR|LOG_USER, "Starting dns2sqlite\n");

   int res = mainloop(argc,argv);
   
//   d2log (LOG_ERR|LOG_USER, "Exiting dns2sqlite\n");
   closelog();
   exit (res);
}
