use Archive::Unrar qw(list_files_in_archive process_file);

print "###### Checking without password ######\n";
!list_files_in_archive('testnopass.rar',"") || die $!;
!process_file('testnopass.rar',undef)|| die $!;

print "###### Checking with password ######\n";
!list_files_in_archive('testwithpass.rar',"test")|| die $!;
!process_file('testwithpass.rar',"test")|| die $!;



