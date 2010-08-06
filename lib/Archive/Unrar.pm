##  Archive::Unrar library 
##  This file is part of Unrar Extract and Recover 2.0
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
use Exporter;
use Win32::API;
use File::Spec;

use constant	{
COMMENTS_BUFFER_SIZE => 16384,
ERAR_END_ARCHIVE =>10,
ERAR_NO_MEMORY =>11, 
ERAR_BAD_DATA  =>12, #"CRC failed.File corrupt";
ERAR_BAD_ARCHIVE =>13,
ERAR_UNKNOWN_FORMAT =>14,
ERAR_EOPEN  =>15,
ERAR_ECREATE   => 16, #"Cannot create directory. Total path and file name length must not exceed 260 characters"; 
ERAR_ECLOSE  => 17,
ERAR_EREAD => 18,
ERAR_EWRITE  => 19,
ERAR_SMALL_BUF=> 20,
ERAR_UNKNOWN  => 21,
ERAR_MISSING_PASSWORD => 22,
ERAR_MAP_DIR_YES=>1,
ERAR_READ_HEADER=>' file header is corrupt',
ERAR_MULTI_BRK => 'multipart but first volume is broken',
ERAR_ENCR_WRONG_PASS => '(headers encrypted) password not correct or file corrupt',
ERAR_WRONG_PASS=>'password not correct or file corrupt',
ERAR_CHAIN_FOUND=>'found in chain.already processed',
ERAR_GENERIC_ALL_ERRORS=> 'if not password protected then file is corrupt.if password protected then password is not correct or file is corrupt',
ERAR_WRONG_FORMAT=>"Check file format........probably it's another format i.e ZIP disguised as a RAR"
};

our @EXPORT = qw(process_file ERAR_BAD_DATA ERAR_ECREATE ERAR_MULTI_BRK ERAR_ENCR_WRONG_PASS ERAR_WRONG_PASS
ERAR_CHAIN_FOUND ERAR_GENERIC_ALL_ERRORS ERAR_WRONG_FORMAT ERAR_MAP_DIR_YES ERAR_MISSING_PASSWORD ERAR_READ_HEADER) ;
our @EXPORT_OK = qw(list_files_in_archive);

our $VERSION = '2.0.1';

our (
    $RAROpenArchiveEx, $RARCloseArchive, $RAROpenArchive, $RARReadHeader,
    $RARReadHeaderEx,  $RARProcessFile,  $RARSetPassword, %donotprocess);

################ PRIVATE METHODS ################ 

sub declare_win32_functions {
	
    $RAROpenArchiveEx = new Win32::API( 'unrar.dll', 'RAROpenArchiveEx', 'P', 'N' );
    $RARCloseArchive =  new Win32::API( 'unrar.dll', 'RARCloseArchive', 'N', 'N' );
    $RAROpenArchive = new Win32::API( 'unrar.dll', 'RAROpenArchive', 'P', 'N' );
    $RARReadHeader = new Win32::API( 'unrar.dll', 'RARReadHeader', 'NP', 'N' );
    $RARProcessFile = new Win32::API( 'unrar.dll', 'RARProcessFile', 'NNPP', 'N' );
    $RARSetPassword = new Win32::API( 'unrar.dll', 'RARSetPassword', 'NP', 'V' );
	  
	  die "Cannot define function.Unrar.dll missing?" if (!defined $RAROpenArchiveEx || !defined $RARCloseArchive || !defined $RAROpenArchive
	       || !defined $RARReadHeader || !defined $RARProcessFile || !defined $RARSetPassword);
		  
		  return 1;
		
}

sub free_pointers {
   $RAROpenArchiveEx = undef;
    $RARCloseArchive = undef;
    $RAROpenArchive = undef;
    $RARReadHeader = undef;
    $RARProcessFile = undef;
    $RARSetPassword =undef;
	  return 1;
}

sub extract_headers {

    my ($file,$password) = @_;
	die "Fatal error $!" if (!-e $file);
	
    my $CmtBuf = pack('x'.COMMENTS_BUFFER_SIZE);
    my $continue;
	
	declare_win32_functions;
		
    my $RAROpenArchiveDataEx =
      pack( 'pLLLPLLLLL32', $file, 0, 2, 0, $CmtBuf, COMMENTS_BUFFER_SIZE, 0, 0, 0,0 );
	
	
    my $handle = $RAROpenArchiveEx->Call($RAROpenArchiveDataEx);

    my (
        undef,  undef, undef,  undef, $CmtBuf1,
        undef,    $CmtSize, $CmtState, $flagsEX, undef
    ) = unpack( 'pLLLP'.COMMENTS_BUFFER_SIZE.'LLLLL32', $RAROpenArchiveDataEx );

	
	
	if ($handle == 0) {
	  free_pointers() &&  return (undef,undef,ERAR_WRONG_FORMAT);
	}
	 else {
		!$RARCloseArchive->Call($handle) || die "Fatal error $!";
	 }
		
	
	my $RAROpenArchiveData = pack( 'pLLPLLL', $file, 2, 0, undef, 0, 0, 0 );
	
    my $handle = $RAROpenArchive->Call($RAROpenArchiveData);
	
	if ($handle == 0) {
	  free_pointers () &&  return (undef,undef,ERAR_WRONG_FORMAT);
	}
	 
		
	my $RARHeaderData = pack( 'x260x260LLLLLLLLLLPLLL',
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 );


    my ( $arcname, $filename, $flags);
  

 
	unless ($flagsEX & 128){
		if ($RARReadHeader->Call( $handle, $RARHeaderData )) {
				!$RARCloseArchive->Call($handle) || die "Fatal error $!";		
				free_pointers() && 	return (undef,undef,ERAR_READ_HEADER);
		}
		else
		{	 
			( $arcname, $filename, $flags ) =  unpack( 'Z260Z260L', $RARHeaderData );
			$arcname =~ s/\0.*$//;
			$filename =~ s/\0.*$//;
		}
	}
	
	printf( "\nFile:    %s\n", $file );
	printf( "\nArchive: %s\n", $arcname );
	printf( "\n(First)Internal Filename: %s\n", $filename );
	printf( "\nPassword?:\t%s", 
	      ($flagsEX & 128)? "yes" :( $flags & 4 )     ? "yes" : "no" ); 
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

	if ($CmtState==1) {
			$CmtBuf1 = unpack( 'A' . $CmtSize, $CmtBuf1 );
			printf( "\nEmbedded Archive Comments (limited to first 16K) :%s\n", $CmtBuf1 );
		}
	
    if ( exists $donotprocess{$file} ) {
        $continue = ERAR_CHAIN_FOUND;		
    } 
	elsif (!($flagsEX & 256) && !($flagsEX & 128) && ($flagsEX & 1)) {
            #not blockencrypted and not first volume and part of multi archive
			#multipart and not the first volume...no need to process...skipping....
            $continue=ERAR_MULTI_BRK;
		}
	  		
			
   !$RARCloseArchive->Call($handle) || die "Fatal error $!";

   free_pointers() &&  return ( $flagsEX & 128, $flags & 4 , $continue);
}

################ PUBLIC METHODS ################ 

sub list_files_in_archive {
	
   my $caller_sub = ( caller(1) )[3];

	my ($file,$password) = @_;
    my ( $blockencrypted, $pass_req, $continue ) = extract_headers($file);
	
    my $blockencryptedflag;
	my $errorcode;

	declare_win32_functions;
	my $RAROpenArchiveDataEx =
      pack( 'pLLLPLLLLL32', $file, 0, 2, 0, undef, 0, 0, 0, 0,0 );
	   	     
    my $handle = $RAROpenArchiveEx->Call($RAROpenArchiveDataEx);
        	
	if ($handle == 0 ) {
	 free_pointers() && return ERAR_WRONG_FORMAT;
	 }
	 
      
	my $RARHeaderData = pack( 'x260x260LLLLLLLLLLPLLL',
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, undef, 0, 0, 0 );

    if ($blockencrypted || $pass_req) { 

        if ($password) {
            $RARSetPassword->Call( $handle, $password );
        }
        else {
			!$RARCloseArchive->Call($handle) || die "Fatal error $!";
				free_pointers() &&	return ERAR_MISSING_PASSWORD;
        }
    }

    while ( ( $RARReadHeader->Call( $handle, $RARHeaderData ) ) == 0 ) {
	    $blockencryptedflag="yes";
        
		my $processresult = $RARProcessFile->Call( $handle, 0, 0, 0 );
        
		if ( $processresult != 0 ) {
            $errorcode=$processresult; 
            #probably wrong password but check unrar.dll documentation for error description
            last;
        }
        else {	    
            my @files = unpack( 'Z260Z260', $RARHeaderData );
			$files[0] =~ s/\\0.*//;
           	$donotprocess{ $files[0] } = 1;
			
			if ($caller_sub !~ /process_file$/) {
				print "Archive contents : ", $files[1],"\n";	
				}
        }

    }
    
	if ($blockencrypted && (!defined($blockencryptedflag))) {
		$errorcode=ERAR_ ENCR_WRONG_PASS;
	}
	
		
	!$RARCloseArchive->Call($handle) || die "Fatal error $!";
	free_pointers() &&	return $errorcode;
}

sub process_file {
	
    my ($file,$password,$output_dir_path,$selection,$callback) = @_;
    my ( $blockencrypted, $pass_req, $continue) = extract_headers($file);
	
	my $errorcode;
	my $directory;
	
    my $blockencryptedflag;
	
	if (defined($output_dir_path)) {
	   $directory=$output_dir_path;
	   }
	
	if ($selection==ERAR_MAP_DIR_YES) {
		my (undef,$directories,$file) = File::Spec->splitpath( $file );
		my $temp;
		( $temp = $file ) =~ s/\.rar$//i;
		$directory=$directory."\\".$temp;
	}

    return ($errorcode=$continue,$directory) if ($continue);
					
	declare_win32_functions;  

	my $RAROpenArchiveDataEx =
      pack( 'pLLLPLLLLL32', $file, 0, 1, 0, undef, 0, 0, 0, 0,0 );
	  
	 
	   	     
    my $handle = $RAROpenArchiveEx->Call($RAROpenArchiveDataEx);
     
 
	if ($handle == 0 ) {
	 	free_pointers() && 	return (ERAR_WRONG_FORMAT,$directory);
	 }

    if ( $blockencrypted || $pass_req ) {

        if ($password) {
            $RARSetPassword->Call( $handle, $password );
		}
        else {
			!$RARCloseArchive->Call($handle) || die "Fatal error $!";
				free_pointers() && 	return (ERAR_MISSING_PASSWORD,$directory);
        }
    }
	
	my $RARHeaderData = pack( 'x260x260LLLLLLLLLLPLLL',
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, undef, 0, 0, 0 );

 
    my $x=0;
	my $y=0;
	
	while ( ( $RARReadHeader->Call( $handle, $RARHeaderData ) ) == 0 ) {
	$blockencryptedflag="yes";
	
	
	
    	$y++;
		if ($y > 1) {print "...processing...";print ++$x} ;
		print "\n";
		
		$callback->(@_) if defined($callback);
				
     	my $processresult = $RARProcessFile->Call( $handle, 2, $directory, 0 );
		
		if ( $processresult != 0 ) {
            $errorcode=$processresult; 
			#probably wrong password but check unrar.dll documentation for error 	
			#description
            last;
        }
	
    }
	
	!$RARCloseArchive->Call($handle) || die "Fatal error $!";
	free_pointers(); 
		
	if ($blockencrypted && (!defined($blockencryptedflag))) {
	     $errorcode=ERAR_ENCR_WRONG_PASS;	 
	}
	elsif ($pass_req && defined($errorcode)) {
		$errorcode=ERAR_WRONG_PASS;
	}
	elsif (defined($errorcode)) {
		$errorcode;
		#do nothing or ERAR_GENERIC_ALL_ERRORS;
	}
	elsif ($blockencrypted && (!defined($errorcode))) {
	       $errorcode=list_files_in_archive( $file, $password );	
	} 
	elsif (!defined $errorcode) {
       $errorcode=list_files_in_archive( $file, $password );
	} 
	
	return ($errorcode,$directory);
}

 
1;
__END__

=head1 NAME

Archive::Unrar - is a procedural module that provides manipulation (extraction and listing of embedded information) of compressed RAR format archives by interfacing with the unrar.dll dynamic library for Windows.

=head1 SYNOPSIS

	use Archive::Unrar;
	
	Usage without password :
	list_files_in_archive($file,undef);
	process_file($file,undef); 

	Usage with password :
	list_files_in_archive($file,$password);
	process_file($file,$password); 
	list_files_in_archive("c:\\input_dir\\testwithpass.rar","mypassword");
	process_file("c:\\input_dir\\testwithpass.rar","mypassword"); 
	
	If archive in the same directory as the caller :
	list_files_in_archive("testwithpass.rar","mypassword");
	process_file("testwithpass.rar","mypassword"); 
	
	Absolute path if RAR archive is not in the same directory as the caller :
	list_files_in_archive("c:\\input_dir\\testwithpass.rar","mypassword");
	process_file("c:\\input_dir\\testwithpass.rar","mypassword"); 
		
	Optionally, provide output directory;
	if directory does not exist then it will be automatically created
	if output directory is not provided then the file is extracted in the same directory the caller :
	process_file("c:\\input_dir\\testwithpass.rar","mypassword","c:\\output_dir"); 
	process_file("c:\\input_dir\\testnopass.rar",undef,"c:\\output_dir"); 
		
	Optionally, provide Selection :
	If Selection equals ERAR_MAP_DIR_YES then 'Map directory to Archive name'
	process_file("c:\\input_dir\\testwithpass.rar","mypassword","c:\\output_dir",ERAR_MAP_DIR_YES); 
		
	If Selection<>ERAR_MAP_DIR_YES then 'Do not Map directory to Archive name'
	process_file("c:\\input_dir\\testwithpass.rar","mypassword","c:\\output_dir",undef); 
		

=head1 DESCRIPTION

Archive::Unrar is a procedural module that provides manipulation (extraction and listing of embedded information) of compressed RAR format archives by interfacing with the unrar.dll dynamic library for Windows.

It exports two functions : explicitly list_files_in_archive and by default process_file

The first one lists details embedded into the archive (files bundled into the .rar archive,archive's comments and header info) and the latter extracts the files from the archive.

list_files_in_archive takes two parameters;the first is the file name and the second is the password required by the archive.
If no password is required then just pass undef or the empty string as the second parameter

process_file takes five parameters;the first is the file name, the second is the password required by the archive, the third is the directory that the file's contents will be extracted to. The fourth dictates if a directory will created (pass ERAR_MAP_DIR_YES) with the
same as name as the archive (Map directory to archive name). The last one refers to a callback,optionally.
If no password is required then just pass undef or the empty string as the second parameter
Function prototype :  ($file,$password,$output_dir_path,$selection,$callback)

process_file returns $errorcode and $directory.If $errorcode is undefined it means that
the function executed with no errors. If not, $errorcode will contain an error description.
$directory is the directory where the archive was extracted to :

($errorcode,$directory)=process_file($file,$password);
print "There was an error : $errorcode" if defined($errorcode);

list_files_in_archive returns $errorcode:

$errorcode=list_files_in_archive($file,$password);
print "There was an error : $errorcode" if defined($errorcode);

Version 2.0 includes support for custom callback while processing of files (line 312 : $callback->(@_) if defined($callback))
For an example of its usefulness take a look at : L<http://sourceforge.net/projects/unrarextractrec/>
The Unrar_Extract_and_Recover.pl script uses a callback (my $callback=sub { $gui::top->update() }) for allowing the updating of GUI events while the process_file function of Unrar.pm is engaged into extracting the file (which is a long running activity), so the GUI is more responsive, minimizes the 'freezing' time and most importantly allows Pausing while the file is being processed/extracted

=head2 Version 2.0 Notes

Version 2.0 is a mature release - major update/rewrite. Upgrading to this version is strongly recommended. 

fixes runaway pointer bug which could result in random hangs;in previous versions the cleanup/pointer deallocation 
was left up to the caller of the module which would lead to issues like runaway pointers. Now the module deallocates
pointers by itself making it truly self-contained

fixes some incorrect mappings between Perl and dll's C structures

better error checking

some optimizations

using constants for error description

added support for custom callback while processing file (line 312 : $callback->(@_) if defined($callback))

=head1 PREREQUISITES

Must have unrar.dll in %SystemRoot%\System32.

Get UnRAR dynamic library for Windows software developers at L<http://www.rarlab.com/rar/UnRARDLL.exe >

This package includes the dll,samples,dll internals and error description 

=head2 TEST AFTER INSTALLATION

After module is installed run test\mytest.pl.
If all is well then you should see the following files :

test no pass succedeed.txt, in the current directory 

test with pass succedeed.txt, in the current directory

A file 'test with pass succedeed1.txt' inside newly created directory 'c:\output_dir' 

A file 'test with pass succedeed2.txt'  newly created directory 'c:\output_dir\testwithpass2' which demonstrates the usage of constant ERAR_MAP_DIR_YES

=head2 EXPORT

process_file function and most error description constants, by default.
list_files_in_archive explicitly.


=head1 AUTHOR

Nikos Vaggalis <F<nikos.vaggalis@gmail.com>>

For a complete application based on the module look at :
L<http://sourceforge.net/projects/unrarextractrec/>


=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Nikos Vaggalis

This library and all of its earlier versions are licenced under GPL3.0

=cut
