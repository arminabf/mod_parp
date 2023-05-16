#!/bin/sh

cd `dirname $0`

PFX=[`basename $0`]

HTT_ERRORS=0

for E in `ls scripts/*.htt`; do
    ./htt.sh -Ts $E
    if [ $? -ne 0 ]; then
        HTT_ERRORS=`expr $HTT_ERRORS + 1`
    fi
done

echo "$PFX: $HTT_ERRORS ERRORS"
if [ $HTT_ERRORS -ne 0 ]; then
    exit 1
fi
exit 0

