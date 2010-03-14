use Archive::Unrar qw(process_file);

print "###### Checking without password ######\n";
($errorcode,$directory)=process_file('testnopass.rar',undef);

print "###### Checking with password ######\n";
($errorcode,$directory)=process_file('testwithpass.rar',"test");

($errorcode,$directory)=process_file('testwithpass1.rar',"test1",'c:\\output_dir');

#($errorcode,$directory)=process_file('testwithpass.rar',"test",'c:\\output_dir',1);





