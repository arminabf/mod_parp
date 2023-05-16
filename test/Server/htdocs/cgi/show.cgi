#!/usr/bin/perl -w

use strict;
use CGI;

my $cgi = new CGI;
my $method = $ENV{"REQUEST_METHOD"};
my $user = $ENV{"REMOTE_USER"};
my $action = $cgi->param('action');

my $file = $cgi->param("access_log");
my $fname = $file;
open DAT,'>'.$fname or die 'Error processing file: ',$!;
binmode $file;
binmode DAT;

my $data;
while(read $file,$data,1024) {
  print DAT $data;
}
close DAT;


print "Content-type: text/plain\r\n";
print "\r\n";
print "$method: action=$action\n";
print "$file\n";
print "done\n";

