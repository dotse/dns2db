#!/bin/sh
# 
#  Copyright (c) 2007 .SE (The Internet Infrastructure Foundation).
#                   All rights reserved.
# 
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  
#  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
#  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
#  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
#  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
#  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
#  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#  ##################################################################### 


### Start script for DNS2db

# Check for configfile
if [ -e /etc/dns2db.conf ]; then
	. /etc/dns2db.conf
else
	echo "Configfile not found, create /etc/dns2db.conf and try again."
	exit 1
fi

# Set up logging function
llogger() {
  echo `date` " - [DNS2DB] - $*" | tee -a ${LOGFILE}
}

sstart() {
  sstatus
  if [ $? -ne 0 ]; then
    TRACEDNS_PARAMETERS=
    if [ "${PROMISCUOUS}" == "Y" ]; then
      llogger "Using PROMISCUOUS"
      TRACEDNS_PARAMETERS=-p
    fi

    DNS2SQLITE_PARAMETERS=
    if [ "${QUERIES}" == "Y" ]; then
      llogger "Using QUERIES"
      DNS2SQLITE_PARAMETERS=-q
    fi

    if [ "${REPLIES}" == "Y" ]; then
      llogger "Using REPLIES"
      DNS2SQLITE_PARAMETERS="${DNS2SQLITE_PARAMETERS} -r"
      DNS2SQLITE_PARAMETERS=`echo ${DNS2SQLITE_PARAMETERS} | sed 's/  / /g'`
    fi

    if [ "${OVERWRITE}" == "Y" ]; then
      llogger "Using OVERWRITE"
      DNS2SQLITE_PARAMETERS="${DNS2SQLITE_PARAMETERS} -o"
      DNS2SQLITE_PARAMETERS=`echo ${DNS2SQLITE_PARAMETERS} | sed 's/  / /g'`
    fi

    SNAPLEN=`echo ${SNAPLEN:=65535}`
    PARTITION_INTERVAL=`echo ${PARTITION_INTERVAL:=5}`
    DBLOCATION=`echo ${DBLOCATION:=/tmp}`


    llogger "Starting dns2db"
    llogger "tracedns ${TRACEDNS_PARAMETERS} -s ${SNAPLEN} -f ${FILTER} ${TRACE_SRCS}"
    llogger "dns2sqlite ${DNS2SQLITE_PARAMETERS} -t ${TEMPLATEDB} -d ${DATABASE} -f ${DBLOCATION} -i ${PARTITION_INTERVAL}"

    nohup tracedns ${TRACEDNS_PARAMETERS} -s ${SNAPLEN} -f "${FILTER}" ${TRACE_SRCS} | dns2sqlite ${DNS2SQLITE_PARAMETERS} -t ${TEMPLATEDB} -d ${DATABASE} -f ${DBLOCATION} -i ${PARTITION_INTERVAL} | logger -i -t DNS2DB 2>&1 &

    sleep 3
    ps | grep [d]ns2sqlite | awk '{print $1}' > ${DNS2DB_PIDFILE}
    ps | grep [t]racedns | awk '{print $1}' >> ${DNS2DB_PIDFILE}
  fi
}

sstop(){
  sstatus
  if [ $? -eq 0 ]; then
    pid=`cat ${DNS2DB_PIDFILE}`
    llogger "Killing dns2db, PID: ${pid}"
    kill -15 ${pid}
    rm -f ${DNS2DB_PIDFILE}
    else
      llogger "dns2db could not be stopped"
  fi
}

sstatus(){
  llogger "Checking status of the server"

  if [ -e ${DNS2DB_PIDFILE} ]; then
    llogger "dns2db is started, PID: `cat ${DNS2DB_PIDFILE}`"
    return 0
  else
    llogger "dns2db is stopped"
    return 1
  fi
}

case "$1" in
   start)
      sstart
      RETVAL=$?
   ;;
   stop)
      sstop
      RETVAL=$?
   ;;
   restart)
      sstop
      sstart
      RETVAL=$?
   ;;
   status)
      sstatus
      RETVAL=$?
   ;;
   *)
   echo "Usage: $0 {start|stop|restart|status}"
   exit 1
esac

exit $RETVAL;

