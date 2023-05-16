#!/bin/bash

cd `dirname $0`

HTTEST=./bin/httest
#HTTEST=/usr/local/bin/httest-2.4.9

${HTTEST} $@
RC=$?
if [ $RC -ne 0 ]; then
    exit $RC
fi

exit 0
