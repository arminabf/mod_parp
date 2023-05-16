#!/bin/bash

. ./include.sh

tar xzSpf ./3thrdparty/$HTTPD.tar.gz
rm -f httpd
ln -s $HTTPD httpd
