use Archive::Unrar;

print "###### Test1 : Checking without password ######\n";
my ($errorcode,$directory)=process_file('testnopass.rar',undef);
 (!defined  $errorcode and print "Test1 successfull\n\n" ) || print "Test1 failed - Errorcode : $errorcode\n\n";

print "###### Test2 : Checking with password ######\n";
my ($errorcode,$directory)=process_file('testwithpass.rar',"test");
 (!defined  $errorcode and print "Test2 successfull\n\n" ) || print "Test2 failed- Errorcode : $errorcode\n\n";

print "###### Test3 : Checking with password ######\n";
my ($errorcode,$directory)=process_file('testwithpass1.rar',"test",'c:\\output_dir');
 (!defined  $errorcode and print "Test3 successfull\n\n" ) || print "Test3 failed - Errorcode : $errorcode\n\n";

print "###### Test4 : Checking with password ######\n";
my ($errorcode,$directory)=process_file('testwithpass2.rar',"test",'c:\\output_dir',ERAR_MAP_DIR_YES);
 (!defined  $errorcode and print "Test4 successfull\n\n" ) || print "Test4 failed- Errorcode : $errorcode\n\n";

 # print "###### Test5 : Checking with password ######\n";
 # #copy testwithpass3.rar to c:\\ for this test to succeed
 # my ($errorcode,$directory)=process_file('c:\\testwithpass3.rar',"test",'c:\\output_dir',ERAR_MAP_DIR_YES);
 # (!defined  $errorcode and print "Test5 successfull\n\n" ) || print "Test5 failed- Errorcode : $errorcode\n\n";
 
 print "###### Test6 : Checking with password ######\n";
my ($errorcode,$directory)=Archive::Unrar::list_files_in_archive('testwithpass.rar',"test");
 (!defined  $errorcode and print "Test6 successfull\n\n" ) || print "Test6 failed- Errorcode : $errorcode\n\n";




