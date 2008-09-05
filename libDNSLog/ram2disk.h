/*
  $Id: ram2disk.h,v 1.3 2007/05/05 16:39:01 calle Exp $
*/

#ifndef _RAM_2_DISK
#define _RAM_2_DISK




/*
  
  Port to FREEBSD and linux and others
  
*/

#ifndef HAVE_STRNDUP
 #define strndup(str,len) strdup(str)
#endif


#define RAM2DISK_COPY_FAILED "Copy failed"
#define RAM2DISK_TEMP_FAILED "Temp File open failed"
#define RAM2DISK_PERM_FAILED "Permanent File open failed"
#define RAM2DISK_UNLINK_FAILED "Unlinking the temporary filde failed"

#define RAM2DISK_OK 1
#define RAM2DISK_ERROR -1


#define RAM2DISK_LINE_BUFFER 1024

int cp_ram2disk(const char *,const char *,char **);

#endif
