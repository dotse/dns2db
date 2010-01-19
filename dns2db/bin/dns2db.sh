#!/bin/sh
case "$1" in
start)
       dns2db.pl 
        exit 0
       ;;


stop)
       dns2db.pl stop

        ;;
restart)
       dns2db.pl stop
       dns2db.pl 
        exit 0

        ;;
*)
        echo "Usage: `basename $0` {start|stop|restart}" >&2
        exit 64
        ;;
esac

