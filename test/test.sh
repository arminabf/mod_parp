#!/bin/bash
# -*-mode: ksh; ksh-indent: 2; -*-

./bootstrap.sh

ERRORS=0
WARNINGS=0

./ctl.sh start
STDS="main_func.htt loop.htt file.htt big.htt textplain.htt texthtml.htt body.htt anybody.htt mix.htt PARPContentLength.htt modify.htt modify_2.htt modify_3.htt modify_4.htt chunked.htt nbytes.htt multipart.htt"
for E in $STDS; do
  ./htt.sh -se scripts/${E}
  if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED $E"
  fi
done
./ctl.sh stop
sleep 1
./ctl.sh start -D DisableModifyBodyHook
STDS="main_func.htt loop.htt file.htt big.htt textplain.htt texthtml.htt body.htt mix.htt PARPContentLength.htt"
for E in $STDS; do
  ./htt.sh -se scripts/${E}
  if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED $E"
  fi
done

./ctl.sh stop
sleep 1
./ctl.sh start -D noerror
sleep 1
./htt.sh -s scripts/error.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED error.htt"
fi
./ctl.sh stop

grep \\$\\$\\$ ../httpd_src/modules/parp/mod_parp.c
if [ $? -ne 1 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern '\$\$\$'"
fi

LINES=`grep fprintf ../httpd_src/modules/parp/mod_parp.c | wc -l | awk '{print $1}'`
if [ $LINES != "0" ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found pattern 'fprintf'"
fi

if [ `grep -c "exit signal" Server/logs/error_log` -gt 0 ]; then
  WARNINGS=`expr $WARNINGS + 1`
  echo "WARNING: found 'exit signal' message"
fi

if [ $WARNINGS -ne 0 ]; then
    echo "ERROR: got $WARNINGS warnings"
fi

if [ $ERRORS -ne 0 ]; then
    echo "ERROR: end with $ERRORS errors"
    exit 1
fi

CFS=`find . -name "*core*"`
if [ "$CFS" != "" ]; then
    echo "ERROR: found core file"
    exit 1
fi

echo "normal end"
exit 0
