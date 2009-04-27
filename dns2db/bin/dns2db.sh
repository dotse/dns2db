#!/bin/sh
case "$1" in
start)
       perl dns2db.pl 
        exit 0
       ;;


stop)
       perl dns2db.pl stop

        ;;
restart)
       perl dns2db.pl stop
       perl dns2db.pl 
        exit 0

        ;;
*)
        echo "Usage: `basename $0` {start|stop|restart}" >&2
        exit 64
        ;;
esac

