#!/bin/bash

TOP=`pwd`
VERSION=`grep "char g_revision" httpd_src/modules/parp/mod_parp.c | awk '{print $6}' | awk -F'"' '{print $2}'`

scp mod_parp-${VERSION}-src.tar.gz ia97lies,parp@frs.sourceforge.net:/home/pfs/project/p/pa/parp/parp/${VERSION}/.
