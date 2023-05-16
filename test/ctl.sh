#!/bin/bash

ulimit -c unlimited

APA24=""
if [ `../httpd/httpd -v | grep -c "Apache/2.4"` -eq 1 ]; then
  APA24="-D apache24"
fi

if [ "$1" = "restart" ]; then
    ../httpd/httpd -d Server -k stop
    sleep 1
    ../httpd/httpd -d Server $APA24 -k start
else
    if [ -n "$2" -a "$1" = "start" ]; then
        shift
        ../httpd/httpd -d Server $APA24 $@
    else
	if [ "$1" = "stop" ]; then
	    ../httpd/httpd -d Server $APA24 -k stop
	    counter=0
	    while [ $counter -lt 10 ]; do
		if [ -f Server/logs/pid ]; then
		    counter=`expr $counter + 1`
		    sleep 1
		else
		    counter=10
		fi
	    done
	else
	    ../httpd/httpd -d Server $APA24 -k $1
	fi
    fi
fi
if [ "$1" = "start" ]; then
    sleep 1
    counter=0
    while [ $counter -lt 10 ]; do
	if [ -f Server/logs/pid  ]; then
	    counter=10
	else
	    counter=`expr $counter + 1`
	    sleep 1
	fi
    done
    ps -p `cat Server/logs/pid` 1>/dev/null 2>/dev/null
    echo $?
fi
