#!/bin/bash

. ./include.sh

MODULE=parp

cd httpd/modules
if [ ! -d $MODULE ]; then
  mkdir $MODULE
fi
cd $MODULE

for E in `find ../../../httpd_src/modules/$MODULE -type f | grep -v CVS `; do
    rm -f `basename $E`
    ln -s $E `basename $E`
done

if [ `echo $HTTPD | grep -c "httpd-2.4"` -eq 1 ]; then
    # link mod_parp_appl to a sep. directory
    echo " skip patched support tools for Apache 2.4"
else
    cd ../../support
    for E in `find ../../httpd_src/support -type f | grep -v CVS `; do
	rm -f `basename $E`
	ln -s $E `basename $E`
    done
fi
