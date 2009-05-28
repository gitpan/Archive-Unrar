# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Archive-Unrar.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 2;
my $dll = $ENV{SYSTEMROOT}.'\System32\unrar.dll'; 

BEGIN { use_ok('Archive::Unrar') };
ok(-e $dll,"Unrardll existence test") or diag("Test failed : $dll not found!! get it from http://www.rarlab.com/rar/UnRARDLL.exe");

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

