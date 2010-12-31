# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Archive-Unrar.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 3;
no warnings;

my $dll = $ENV{SYSTEMROOT}.'\System32\unrar.dll'; 

BEGIN { use_ok('Archive::Unrar') };
ok(-e $dll,"Unrardll existence test") or diag("Test failed : $dll not found!! get it from http://www.rarlab.com/rar/UnRARDLL.exe");
ok (extraction_test()==6,'extraction test');

sub extraction_test {

my ($errorcode,$directory)=process_file(file=>"testnopass.rar",password=>undef);
 !defined($errorcode) || return 1;

my ($errorcode,$directory)=process_file(file=>"testwithpass.rar",password=>"test");
 !defined($errorcode) || return 2;
 
my ($errorcode,$directory)=process_file(file=>"testwithpass1.rar",password=>"test",output_dir_path=>"archive_unrar_test_output_dir");
 !defined($errorcode) || return 3;
 
my ($errorcode,$directory)=process_file(file=>"testwithpass2.rar",password=>"test",output_dir_path=>"archive_unrar_test_output_dir1",selection=>ERAR_MAP_DIR_YES);
 !defined($errorcode) || return 4;
 
my ($errorcode,$directory)=Archive::Unrar::list_files_in_archive(file=>"testwithpass.rar",password=>"test");
 !defined($errorcode) || return 5;
 
 return 6;
}

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

