package Archive::Unrar;

use 5.010000;
use strict;
use base qw(Exporter);
use Win32::API;
use Exporter;
use Carp qw(croak);
use File::Basename;
	
use constant COMMENTS_BUFFER_SIZE => 16384;

our @EXPORT_OK = qw(list_files_in_archive process_file);

our $VERSION = '1.2';

#unrar.dll internal functions
our (
    $RAROpenArchiveEx, $RARCloseArchive, $RAROpenArchive, $RARReadHeader,
    $RARReadHeaderEx,  $RARProcessFile,  $RARSetPassword
);

################ PRIVATE METHODS ################ 

sub declare_win32_functions {
    $RAROpenArchiveEx =
      new Win32::API( 'unrar.dll', 'RAROpenArchiveEx', 'P', 'N' );
    $RARCloseArchive =
      new Win32::API( 'unrar.dll', 'RARCloseArchive', 'N', 'N' );
    $RAROpenArchive = new Win32::API( 'unrar.dll', 'RAROpenArchive', 'P', 'N' );
    $RARReadHeader = new Win32::API( 'unrar.dll', 'RARReadHeader', 'NP', 'N' );
    $RARReadHeaderEx =
      new Win32::API( 'unrar.dll', 'RARReadHeaderEx', 'NP', 'N' );
    $RARProcessFile =
      new Win32::API( 'unrar.dll', 'RARProcessFile', 'NNPP', 'N' );
    $RARSetPassword =
      new Win32::API( 'unrar.dll', 'RARSetPassword', 'NP', 'N' );
	  return 1;
}

sub extract_headers {

    my ($file,$password) = @_;
    my $CmtBuf = pack('x'.COMMENTS_BUFFER_SIZE);
    my $continue;
	
    my $RAROpenArchiveDataEx =
      pack( 'ppLLPLLLLx32', $file, undef, 2, 0, $CmtBuf, COMMENTS_BUFFER_SIZE, 0, 0, 0 );
    my $RAROpenArchiveData = pack( 'pLLpLLL', $file, 2, 0, undef, 0, 0, 0 );
    my $RARHeaderData = pack( 'x260x260LLLLLLLLLLpLL',
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, undef, 0, 0 );

    my $handle1 = $RAROpenArchiveEx->Call($RAROpenArchiveDataEx)
      || croak "RAROpenArchiveEx failed";

    my (
        $arcname1, undef,    undef,     undef, $CmtBuf1,
        undef,    $CmtSize, $CmtState, $flagsEX
    ) = unpack( 'ppLLP'.COMMENTS_BUFFER_SIZE.'LLLLL', $RAROpenArchiveDataEx );

    !$RARCloseArchive->Call($handle1) || croak "RARCloseArchive failed";

	
    my $handle2 = $RAROpenArchive->Call($RAROpenArchiveData)
      || croak "RAROpenArchive failed";

    $flagsEX & 128
      || !$RARReadHeader->Call( $handle2, $RARHeaderData )
      || croak "RARReadHeader failed";
		
    my ( $arcname2, $filename, $flags, $packsize ) =
      unpack( 'A260A260LL', $RARHeaderData );

    $CmtBuf1 = unpack( 'A' . $CmtSize, $CmtBuf1 );
    printf( "\nComments :%s\n", $CmtBuf1 );

    printf( "\nArchive %s\n", $arcname2 );
	#printf( "\nFilename %s\n", $filename );
    printf( "\nVolume:\t\t%s",     ( $flagsEX & 1 )   ? "yes" : "no" );
    printf( "\nComment:\t%s",      ( $flagsEX & 2 )   ? "yes" : "no" );
    printf( "\nLocked:\t\t%s",     ( $flagsEX & 4 )   ? "yes" : "no" );
    printf( "\nSolid:\t\t%s",      ( $flagsEX & 8 )   ? "yes" : "no" );
    printf( "\nNew naming:\t%s",   ( $flagsEX & 16 )  ? "yes" : "no" );
    printf( "\nAuthenticity:\t%s", ( $flagsEX & 32 )  ? "yes" : "no" );
    printf( "\nRecovery:\t%s",     ( $flagsEX & 64 )  ? "yes" : "no" );
    printf( "\nEncr.headers:\t%s", ( $flagsEX & 128 ) ? "yes" : "no" );
    printf( "\nFirst volume:\t%s\n\n",
        ( $flagsEX & 256 ) ? "yes" : "no or older than 3.0" );

    if (!($flagsEX & 256) && !($flagsEX & 128) && ($flagsEX & 1)) {
            #not blockencrypted and not first volume and part of multi archive
            $continue="no";
		}
       		
    !$RARCloseArchive->Call($handle2) || croak "RARCloseArchive failed";
    return ( $flagsEX & 128, $flags & 4 , $continue);
}

################ PUBLIC METHODS ################ 

sub list_files_in_archive {
    my ($file,$password) = @_;
    my ( $blockencrypted, $locked, $continue ) = extract_headers($file);
	
    my $blockencryptedflag;
	my $errorcode;
	
    my $RAROpenArchiveDataEx_for_extracting =
      pack( 'ppLLpLLLLx32', $file, undef, 2, 0, undef, 0, 0, 0, 0 );
    my $handle = $RAROpenArchiveEx->Call($RAROpenArchiveDataEx_for_extracting)
      || croak "RAROpenArchiveEx failed";
    my $RARHeaderData = pack( 'x260x260LLLLLLLLLLpLL',
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, undef, 0, 0, 0 );

    if ($blockencrypted) { #no need to check for $locked

        if ($password) {
            $RARSetPassword->Call( $handle, $password );
        }
        else {
			!$RARCloseArchive->Call($handle) || croak "$RARCloseArchive failed";
			return $errorcode="requires password";
        }
    }

    while ( ( $RARReadHeader->Call( $handle, $RARHeaderData ) ) == 0 ) {
	    $blockencryptedflag="yes";
        my $processresult = $RARProcessFile->Call( $handle, 0, undef, undef );
        if ( $processresult != 0 ) {
            $errorcode=$processresult; #probably wrong password but check unrar.dll documentation for error description
            last;
        }
        else {	    
            my @files = unpack( 'A260A260LLLLLLLLLLpLL', $RARHeaderData );
            print "File\t\t\t\t\tSize\n";
            print "-------------------------------------------\n";
            print "$files[0]\\$files[1]\t\t$files[4]\n\n";
        }

    }
    
	if ($blockencrypted && (!defined($blockencryptedflag))) {
		$errorcode="headers encrypted and password not correct";
	}
	
    !$RARCloseArchive->Call($handle) || croak "$RARCloseArchive failed";
	return $errorcode;
}

sub process_file {
    my ($file,$password) = @_;
    my ( $blockencrypted, $locked, $continue ) = extract_headers($file);
	
	my $errorcode;
	return ($errorcode="multipart") if ($continue); 
	
    my($filename, $directory, undef) = fileparse($file);
    my $blockencryptedflag;
	

    my $RAROpenArchiveDataEx_for_extracting =
      pack( 'ppLLpLLLLx32', $file, undef, 1, 0, undef, 0, 0, 0, 0 );
    my $RARHeaderData = pack( 'x260x260LLLLLLLLLLpLL',
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, undef, 0, 0 );

    my $handle = $RAROpenArchiveEx->Call($RAROpenArchiveDataEx_for_extracting)
      || croak "RAROpenArchiveEx failed";

    if ( $blockencrypted || $locked ) {

        if ($password) {
            $RARSetPassword->Call( $handle, $password );
        }
        else {
			!$RARCloseArchive->Call($handle) || croak "$RARCloseArchive failed";
			return $errorcode="requires password";
        }
    }

    while ( ( $RARReadHeader->Call( $handle, $RARHeaderData ) ) == 0 ) {
	    $blockencryptedflag="yes";
        my $processresult = $RARProcessFile->Call( $handle, 2, $directory, undef );
               
		if ( $processresult != 0 ) {
            $errorcode=$processresult; #probably wrong password but check unrar.dll documentation for error description
            last;
        }

    }

	 if ($blockencrypted && (!defined($blockencryptedflag))) {
	     $errorcode="headers encrypted and password not correct";
	}
	
    !$RARCloseArchive->Call($handle) || croak "RRARCloseArchive failed";
	return $errorcode;
}

declare_win32_functions();

1;
__END__

=head1 NAME

Archive::Unrar - is a procedural module that provides manipulation (extraction and listing of embedded information) of compressed RAR format archives by interfacing with the unrar.dll dynamic library for Windows.

=head1 SYNOPSIS

	use Archive::Unrar qw(list_files_in_archive process_file);
	
	#usage with password
		list_files_in_archive($file,$password);
		process_file($file,$password); 
	
	#usage without password
		list_files_in_archive($file,undef);
		process_file($file,undef); 
		
	#if RAR archive in the same directory as the caller
		list_files_in_archive("testwithpass.rar","mypassword");
		process_file("testwithpass.rar","mypassword"); 
	
	#absolute path if RAR archive is not in the same directory as the caller
		list_files_in_archive("c:\\input_dir\\testwithpass.rar","mypassword");
		process_file("c:\\input_dir\\testwithpass.rar","mypassword"); 
	
	#optionally, provide output directory as the last parameter,
	#if directory does not exist then it will be automatically created
	#if output directory is not provided then the file is extracted 
	#in the same directory the caller
		list_files_in_archive("c:\\input_dir\\testwithpass.rar","mypassword");
		process_file("c:\\input_dir\\testwithpass.rar","mypassword","c:\\output_dir"); 
		process_file("c:\\input_dir\\testnopass.rar",undef,"c:\\output_dir"); 
		

=head1 DESCRIPTION

Archive::Unrar is a procedural module that provides manipulation (extraction and listing of embedded information) of compressed RAR format archives by interfacing with the unrar.dll dynamic library for Windows.

It uses two functions : list_files_in_archive and process file

The first one lists details embedded into the archive (files bundled into the .rar archive,archive's comments and header info) and the latter extracts the files from the archive.

list_files_in_archive takes two parameters;the first is the file name and the second is the password required by the archive.
If no password is required then just pass undef or the empty string as the second parameter

process_file takes three parameters;the first is the file name, the second is the password required by the archive
and the third is the directory that the file's contents will be extracted to.
If no password is required then just pass undef or the empty string as the second parameter

Both procedures return undef if successfull, and an error description if something went wrong

	$result=process_file($file,$password);
	print "There was an error : $result" if defined($result);

=head1 PREREQUISITES

Must have unrar.dll in %SystemRoot%\System32.

Get UnRAR dynamic library for Windows software developers at L<http://www.rarlab.com/rar/UnRARDLL.exe >

This package includes the dll,samples,dll internals and error description 

=head1 TEST AFTER INSTALLATION

After module is installed run test\mytest.pl.
If all is well then you should see two files in the directory :

	test no pass succedeed.txt
	test with pass succedeed.txt

=head2 EXPORT

None by default.

=head1 AUTHOR

Nikos Vaggalis <F<nikos.vaggalis@gmail.com>>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Nikos Vaggalis

This library and all of its earlier versions are licenced under GPL3.0

For a complete application based on the module look at :
L<http://sourceforge.net/projects/unrarextractrec/>

=cut
