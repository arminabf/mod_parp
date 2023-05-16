#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-

. ./include.sh

cd httpd
if [ `echo $HTTPD | grep -c "httpd-2.4"` -eq 1 ]; then
  echo "configure Apache 2.4"
  ./configure \
   --with-apr=`pwd`/../../apr \
   --with-mpm=worker \
   --enable-modules=all \
   --enable-mods-static=all \
   --with-module=parp:parp,parp:parp_appl
  RC=$?
else
  echo "configure Apache 2.x"
  ./buildconf
  if [ $? -ne 0 ]; then
    echo "ERROR"
    exit 1
  fi
  CFLAGS="-g -Wall" ./configure \
   --prefix=$HOME/local \
   --enable-so \
   --enable-static-support \
   --enable-ssl \
   --enable-proxy \
   --enable-parp=shared \
   --enable-parp-appl=shared
  RC=$?
fi
if [ $RC -ne 0 ]; then
  echo "ERROR"
  exit 1
fi
