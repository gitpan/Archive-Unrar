##  Archive::Unrar library 

##  Copyright (C) 2009 Nikos Vaggalis <nikos.vaggalis@gmail.com>
##  This program is free software; you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation; either version 3 of the License, or
##  (at your option) any later version.

##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.

##  You should have received a copy of the GNU General Public License
##  along with this program; if not, write to the Free Software
##  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

package Archive::Unrar;

use 5.010000;
use strict;
use base qw(Exporter);
use Win32::API;
use Exporter;
use Carp qw(carp);
use File::Basename;
use Cwd qw(getcwd);
use constant COMMENTS_BUFFER_SIZE => 16384;

our @EXPORT_OK = qw(list_files_in_archive process_file);

our $VERSION = '1.3';

#unrar.dll internal functions
our (
    $RAROpenArchiveEx, $RARCloseArchive, $RAROpenArchive, $RARReadHeader,
    $RARReadHeaderEx,  $RARProcessFile,  $RARSetPassword, %donotprocess);

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
      || return (undef,undef,"RAROpenArchiveEx failed");

    my (
        $arcname1, undef,    undef,     undef, $CmtBuf1,
        undef,    $CmtSize, $CmtState, $flagsEX
    ) = unpack( 'ppLLP'.COMMENTS_BUFFER_SIZE.'LLLLL', $RAROpenArchiveDataEx );

    !$RARCloseArchive->Call($handle1) || return (undef,undef,"RARCloseArchive failed");

	
    my $handle2 = $RAROpenArchive->Call($RAROpenArchiveData)
		|| return (undef,undef,"RAROpenArchive failed");

    $flagsEX & 128
      || !$RARReadHeader->Call( $handle2, $RARHeaderData )
			|| return (undef,undef,"RARReadHeader failed");
		
    my ( $arcname2, $filename, $flags, $packsize ) =
      unpack( 'A260A260LL', $RARHeaderData );

    $CmtBuf1 = unpack( 'A' . $CmtSize, $CmtBuf1 );
    
	printf( "\nFile:    %s\n", $file );
	printf( "\nArchive: %s\n", $arcname2 );
	printf( "\n(First)Internal Filename: %s\n", $filename );
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

	printf( "\nEmbedded Archive Comments :%s\n", $CmtBuf1 );
	
    if ( exists $donotprocess{$file} ) {
        $continue = "found in chain.already processed";		
    } 
	elsif (!($flagsEX & 256) && !($flagsEX & 128) && ($flagsEX & 1)) {
            #not blockencrypted and not first volume and part of multi archive
			#multipart and not the first volume...no need to process...skipping....
            $continue="multipart but first volume is broken";
		}
	  		
    !$RARCloseArchive->Call($handle2) || 
		return (undef,undef,"RARReadHeader failed");
    
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
      || return "RAROpenArchiveEx failed";
    my $RARHeaderData = pack( 'x260x260LLLLLLLLLLpLL',
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, undef, 0, 0, 0 );

    if ($blockencrypted) { #no need to check for $locked

        if ($password) {
            $RARSetPassword->Call( $handle, $password )|| return "RARSetPassword failed";
        }
        else {
			!$RARCloseArchive->Call($handle) || return "RARCloseArchive failed";
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
           	$donotprocess{ $files[0] } = 1;
        }

    }
    
	if ($blockencrypted && (!defined($blockencryptedflag))) {
		$errorcode="headers encrypted and password not correct";
	}
	
	
    !$RARCloseArchive->Call($handle) || carp "$RARCloseArchive failed";
	return $errorcode;
}

sub process_file {
    my ($file,$password,$output_dir_path,$selection) = @_;
    my ( $blockencrypted, $locked, $continue ) = extract_headers($file);
	
	my $errorcode;
	my $directory;
	
    my $blockencryptedflag;
	
	if (defined($output_dir_path)) {
	   $directory=$output_dir_path;
	   }
	
	if ($selection==1) {
		my $temp;
		( $temp = $file ) =~ s/\.rar$//i;
		$directory=$directory."\\".$temp;
	}

	return ($errorcode=$continue,$directory) if ($continue); 
	
    my $RAROpenArchiveDataEx_for_extracting =
      pack( 'ppLLpLLLLx32', $file, undef, 1, 0, undef, 0, 0, 0, 0 );
    my $RARHeaderData = pack( 'x260x260LLLLLLLLLLpLL',
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, undef, 0, 0 );

    my $handle = $RAROpenArchiveEx->Call($RAROpenArchiveDataEx_for_extracting)
      || return "RAROpenArchiveEx failed";

    if ( $blockencrypted || $locked ) {

        if ($password) {
            $RARSetPassword->Call( $handle, $password ) || return "RARSetPassword failed";
        }
        else {
			!$RARCloseArchive->Call($handle) || return "RARCloseArchive failed";
			return $errorcode="requires password";
        }
    }

    while ( ( $RARReadHeader->Call( $handle, $RARHeaderData ) ) == 0 ) {
	    $blockencryptedflag="yes";
        my $processresult = $RARProcessFile->Call( $handle, 2, $directory, undef );
               
		if ( $processresult != 0 ) {
            $errorcode=$processresult; 
			#probably wrong password but check unrar.dll documentation for error 	
			#description
            last;
        }

    }

	 if ($blockencrypted && (!defined($blockencryptedflag))) {
	     $errorcode="headers encrypted and password not correct";
	}
	elsif ($blockencrypted || !defined($errorcode)) {
        list_files_in_archive( $file, $password );
    } 
	
    !$RARCloseArchive->Call($handle) || return "RRARCloseArchive failed";
	return ($errorcode,$directory);
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
	
	#optionally, provide output directory,
	#if directory does not exist then it will be automatically created
	#if output directory is not provided then the file is extracted 
	#in the same directory the caller
		process_file("c:\\input_dir\\testwithpass.rar","mypassword","c:\\output_dir"); 
		process_file("c:\\input_dir\\testnopass.rar",undef,"c:\\output_dir"); 
		
	#optionally, provide Selection
	If Selection equals 1 then 'Map directory to Archive name'
    process_file("c:\\input_dir\\testwithpass.rar","mypassword","c:\\output_dir",1); 
	If Selection<>1 then 'Do not Map directory to Archive name'
	process_file("c:\\input_dir\\testwithpass.rar","mypassword","c:\\output_dir",undef); 
		

=head1 DESCRIPTION

Archive::Unrar is a procedural module that provides manipulation (extraction and listing of embedded information) of compressed RAR format archives by interfacing with the unrar.dll dynamic library for Windows.

It uses two functions : list_files_in_archive and process file

The first one lists details embedded into the archive (files bundled into the .rar archive,archive's comments and header info) and the latter extracts the files from the archive.

list_files_in_archive takes two parameters;the first is the file name and the second is the password required by the archive.
If no password is required then just pass undef or the empty string as the second parameter

process_file takes four parameters;the first is the file name, the second is the password required by the archive, the third is the directory that the file's contents will be extracted to and the fourth dictates if a directory will created with the
same as name as the archive (Map directory to archive name).
If no password is required then just pass undef or the empty string as the second parameter

process_file returns $errorcode and $directory.If $errorcode is undefined it means that
the function executed with no errors. If not, $error_code will contain an error description.
$directory is the directory where the archive was extracted to

	($errorcode,$directory)=process_file($file,$password);
	print "There was an error : $result" if defined($result);

list_files_in_archive returns $errorcode

	$errorcode=list_files_in_archive($file,$password);
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
