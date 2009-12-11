use Archive::Unrar qw(list_files_in_archive process_file);

print "###### Checking without password ######\n";
!list_files_in_archive('testnopass.rar',"") || die $!;
!process_file('testnopass.rar',undef)|| die $!;

print "###### Checking with password ######\n";
!list_files_in_archive('testwithpass.rar',"test")|| die $!;
!process_file('testwithpass.rar',"test")|| die $!;

#!process_file('testwithpass.rar',"test","c:\\output_dir")|| die $!;
#!process_file("c:\\input_dir\\testwithpass.rar",undef,"c:\\output_dir"); 



