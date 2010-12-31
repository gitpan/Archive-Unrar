##  Archive::Unrar library 
##  Copyright (C) 2009,2010 Nikos Vaggalis <nikos.vaggalis@gmail.com>
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
no warnings;

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
our @EXPORT_OK = qw(list_files_in_archive %donotprocess);

our $VERSION = '2.5';

our (%donotprocess);

################ PRIVATE METHODS ################ 

sub declare_win32_functions {
	
	my $RAR_functions_ref = shift;
	
	
 %$RAR_functions_ref = (   
			RAROpenArchiveEx => new Win32::API( 'unrar.dll', 'RAROpenArchiveEx', 'P', 'N' ),
			RARCloseArchive =>  new Win32::API( 'unrar.dll', 'RARCloseArchive', 'N', 'N' ),
			RAROpenArchive => new Win32::API( 'unrar.dll', 'RAROpenArchive', 'P', 'N' ),
			RARReadHeader => new Win32::API( 'unrar.dll', 'RARReadHeader', 'NP', 'N' ),
			RARProcessFile => new Win32::API( 'unrar.dll', 'RARProcessFile', 'NNPP', 'N' ),
			RARSetPassword => new Win32::API( 'unrar.dll', 'RARSetPassword', 'NP', 'V' )
			);
		
		 
		 while ((undef, my $value) = each(%$RAR_functions_ref)){
                die "Cannot load function" if !defined($value) ;
		   }		       		 
		
		return 1;
}



sub extract_headers {

    my ($file,$password) = @_;
	die "Fatal error $! : $file" if (!-e $file);
	
    my $CmtBuf = pack('x'.COMMENTS_BUFFER_SIZE);
    my $continue;
	
	my %RAR_functions;
	declare_win32_functions(\%RAR_functions);
		
    my $RAROpenArchiveDataEx_struct =
      pack( 'pLLLPLLLLL32', $file, 0, 2, 0, $CmtBuf, COMMENTS_BUFFER_SIZE, 0, 0, 0,0 );
	
	
    my $handle = $RAR_functions{RAROpenArchiveEx}->Call($RAROpenArchiveDataEx_struct);

   my ( $CmtBuf1, $CmtSize, $CmtState, $flagsEX ) = 
						(unpack( 'pLLLP'.COMMENTS_BUFFER_SIZE.'LLLLL32', $RAROpenArchiveDataEx_struct ))[4,6,7,8];


	if ($handle == 0) {
	   return (undef,undef,ERAR_WRONG_FORMAT);
	}
	 else {
		!$RAR_functions{RARCloseArchive}->Call($handle) || die "Fatal error $!";
	 }

	my $RAROpenArchiveData_struct = pack( 'pLLPLLL', $file, 2, 0, undef, 0, 0, 0 );
	
    my $handle = $RAR_functions{RAROpenArchive}->Call($RAROpenArchiveData_struct);
	
	if ($handle == 0) {
	   return (undef,undef,ERAR_WRONG_FORMAT);
	}
	 
		
	my $RARHeaderData_struct = pack( 'x260x260LLLLLLLLLLPLLL',
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 );


    my ( $arcname, $filename, $flags);
  

 
	unless ($flagsEX & 128){
		if ($RAR_functions{RARReadHeader}->Call( $handle, $RARHeaderData_struct )) {
				!$RAR_functions{RARCloseArchive}->Call($handle) || die "Fatal error $!";		
				return (undef,undef,ERAR_READ_HEADER);
		}
		else
		{	 
			( $arcname, $filename, $flags ) =  unpack( 'Z260Z260L', $RARHeaderData_struct );
			$arcname  =~s/\0//g;
			$filename =~s/\0//g;
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
			printf( "\nEmbedded Archive Comments (limited to first 16K) : << %s", $CmtBuf1. " >>\n" );
		}
	
    if ( exists $donotprocess{$file} ) {
        $continue = ERAR_CHAIN_FOUND;		
    } 
	elsif (!($flagsEX & 256) && !($flagsEX & 128) && ($flagsEX & 1)) {
            #not blockencrypted and not first volume and part of multi archive
			#multipart and not the first volume...no need to process...skipping....
            $continue=ERAR_MULTI_BRK;
		}
	  		
			
   !$RAR_functions{RARCloseArchive}->Call($handle) || die "Fatal error $!";

  return ( $flagsEX & 128, $flags & 4 , $continue);
}

################ PUBLIC METHODS ################ 

sub list_files_in_archive {
	
   my $caller_sub = ( caller(1) )[3];
   my %params=@_;

	my ($file,$password) = @params{qw (file password)};
	
    my ( $blockencrypted, $pass_req, $continue ) = extract_headers($file);
	
    my $blockencryptedflag;
	my $errorcode;

	my %RAR_functions;
	declare_win32_functions(\%RAR_functions);
	
	my $RAROpenArchiveDataEx_struct =
      pack( 'pLLLPLLLLL32', $file, 0, 2, 0, undef, 0, 0, 0, 0,0 );
	   	     
    my $handle = $RAR_functions{RAROpenArchiveEx}->Call($RAROpenArchiveDataEx_struct);
        	
	if ($handle == 0 ) {
	 return ERAR_WRONG_FORMAT;
	 }
	 
      
	my $RARHeaderData_struct = pack( 'x260x260LLLLLLLLLLPLLL',
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, undef, 0, 0, 0 );

    if ($blockencrypted || $pass_req) { 

        if ($password) {
            $RAR_functions{RARSetPassword}->Call( $handle, $password );
        }
        else {
			!$RAR_functions{RARCloseArchive}->Call($handle) || die "Fatal error $!";
				return ERAR_MISSING_PASSWORD;
        }
    }

    while ( ( $RAR_functions{RARReadHeader}->Call( $handle, $RARHeaderData_struct ) ) == 0 ) {
	    $blockencryptedflag="yes";
        
		my $processresult = $RAR_functions{RARProcessFile}->Call( $handle, 0, 0, 0 );
        
		if ( $processresult != 0 ) {
            $errorcode=$processresult; 
            #probably wrong password but check unrar.dll documentation for error description
            last;
        }
        else {	    
            my @files = unpack( 'Z260Z260', $RARHeaderData_struct );
			$files[0] =~  s/\0//g;
           	$donotprocess{ $files[0] } = 1;
			
			if ($caller_sub !~ /process_file$/) {
				print "Archive contents : ", $files[1],"\n";	
				}
        }

    }
    
	if ($blockencrypted && (!defined($blockencryptedflag))) {
		$errorcode=ERAR_ ENCR_WRONG_PASS;
	}
	
		
	!$RAR_functions{RARCloseArchive}->Call($handle) || die "Fatal error $!";
	return $errorcode;
}

sub process_file {
   my %params=@_;
   
   my ($file,$password,$output_dir_path,$selection,$callback) = @params{qw (file password output_dir_path selection callback) }; 

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
					
	my %RAR_functions;
	declare_win32_functions(\%RAR_functions);

	my $RAROpenArchiveDataEx_struct =
      pack( 'pLLLPLLLLL32', $file, 0, 1, 0, undef, 0, 0, 0, 0,0 );
	     	     
    my $handle = $RAR_functions{RAROpenArchiveEx}->Call($RAROpenArchiveDataEx_struct);
     
 
	if ($handle == 0 ) {
	 	return (ERAR_WRONG_FORMAT,$directory);
	 }

    if ( $blockencrypted || $pass_req ) {

        if ($password) {
            $RAR_functions{RARSetPassword}->Call( $handle, $password );
		}
        else {
			!$RAR_functions{RARCloseArchive}->Call($handle) || die "Fatal error $!";
			return (ERAR_MISSING_PASSWORD,$directory);
        }
    }
	
	my $RARHeaderData_struct = pack( 'x260x260LLLLLLLLLLPLLL',
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, undef, 0, 0, 0 );

 
    my $x=0;
	my $y=0;
	
	while ( ( $RAR_functions{RARReadHeader}->Call( $handle, $RARHeaderData_struct ) ) == 0 ) {
	$blockencryptedflag="yes";
	
	
	
    	$y++;
		if ($y > 1) {print "...processing...";print ++$x} ;
		print "\n";
		
		$callback->(@_) if defined($callback);
				
     	my $processresult = $RAR_functions{RARProcessFile}->Call( $handle, 2, $directory, 0 );
		
		if ( $processresult != 0 ) {
            $errorcode=$processresult; 
			#probably wrong password but check unrar.dll documentation for error 	
			#description
            last;
        }
	
    }
	
	!$RAR_functions{RARCloseArchive}->Call($handle) || die "Fatal error $!";
	
		
	if ($blockencrypted && (!defined($blockencryptedflag))) {
	     $errorcode=ERAR_ENCR_WRONG_PASS;	 
	}
	elsif ($pass_req && defined($errorcode)) {
		$errorcode=ERAR_WRONG_PASS;
	}
	elsif (defined($errorcode)) {
		$errorcode;
		#placeholder for future use
		#do nothing or ERAR_GENERIC_ALL_ERRORS;
	}
	elsif ($blockencrypted && (!defined($errorcode))) {
	       $errorcode=list_files_in_archive(  file=>$file, password=>$password );	
	} 
	elsif (!defined $errorcode) {
       $errorcode=list_files_in_archive(  file=>$file, password=>$password );	
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
	list_files_in_archive(  file=>$file, password=>$password );	
	process_file( file=>$file, password=>$password, output_dir_path=>$output_dir_path, selection=>$selection,callback=>$callback );

	list_files_in_archive(file=>"c:\\input_dir\\test.rar",password=>"mypassword");
			
	Optionally, provide Selection and Callback:
	
	If Selection equals ERAR_MAP_DIR_YES then 'Map directory to Archive name'
	process_file("c:\\input_dir\\test.rar",password=>"mypassword", output_dir_path=>"c:\\outputdir", selection=>ERAR_MAP_DIR_YES,callback=>undef ); 
		
	If Selection<>ERAR_MAP_DIR_YES then 'Do not Map directory to Archive name'
	process_file("c:\\input_dir\\test.rar",password=>"mypassword", output_dir_path=>"c:\\outputdir", selection=>undef,callback=>undef ); 
		

=head1 DESCRIPTION

Archive::Unrar is a procedural module that provides manipulation (extraction and listing of embedded information) of compressed RAR format archives by interfacing with the unrar.dll dynamic library for Windows.

It exports function  "list_files_in_archive" and hash structure "%donotprocess" explicitly 

@EXPORT_OK = qw(list_files_in_archive %donotprocess);

By default it exports function "process_file" and some default error description constants

@EXPORT = qw(process_file ERAR_BAD_DATA ERAR_ECREATE ERAR_MULTI_BRK ERAR_ENCR_WRONG_PASS ERAR_WRONG_PASS
ERAR_CHAIN_FOUND ERAR_GENERIC_ALL_ERRORS ERAR_WRONG_FORMAT ERAR_MAP_DIR_YES ERAR_MISSING_PASSWORD ERAR_READ_HEADER) ;

"list_files_in_archive" lists details embedded into the archive (files bundled into the .rar archive,archive's comments and header info) 
It takes two parameters;the first is the file name and the second is the password required by the archive.
If no password is required then just pass undef or the empty string as the second parameter

"list_files_in_archive" returns $errorcode.If $errorcode is undefined it means that
the function executed with no errors. If not, $errorcode will contain an error description.
$errorcode=list_files_in_archive($file,$password);
print "There was an error : $errorcode" if defined($errorcode);

"process_file" takes five parameters;the first is the file name, the second is the password required by the archive, the third is the directory that the file's contents will be extracted to. The fourth dictates if a directory will created (pass ERAR_MAP_DIR_YES) with the
same as name as the archive (Map directory to archive name). The last one refers to a callback,optionally.
If no password is required then just pass undef or the empty string

"process_file" returns $errorcode and $directory.If $errorcode is undefined it means that
the function executed with no errors. If not, $errorcode will contain an error description.
$directory is the directory where the archive was extracted to :

($errorcode,$directory) = process_file( file=>$file, password=>$password, output_dir_path=>$output_dir_path, selection=>undef,callback=>undef);
print "There was an error : $errorcode" if defined($errorcode);

Version 2.0 upwards includes support for custom callback while processing of files (line 312 : $callback->(@_) if defined($callback))
For an example of its usefulness take a look at : L<http://sourceforge.net/projects/unrarextractrec/>
The Unrar_Extract_and_Recover.pl script uses a callback (my $callback=sub { $gui::top->update() }) for allowing the updating of GUI events while the process_file function of Unrar.pm is engaged into extracting the file (which is a long running activity), so the GUI is more responsive, minimizes the 'freezing' time and most importantly allows Pausing while the file is being processed/extracted

=head2 Version 2.5 Notes

Changed signature of functions "process_file" and "list_files_in_archive" making them use named arguments resulting in cleaner code

Code refactoring

Optimizations

Made module re-entrant by removing all globals except %donotprocess

=head1 PREREQUISITES

Must have unrar.dll in %SystemRoot%\System32.

Get UnRAR dynamic library for Windows software developers at L<http://www.rarlab.com/rar/UnRARDLL.exe >

This package includes the dll,samples,dll internals and error description 

Version 2.0 upwards includes unrar.dll in the distribution and copies it to %SystemRoot%\System32 during the module's instalation
. No need to separately download unrar.dll and install it

=head2 TEST AFTER INSTALLATION

run test\mytest.pl

=head2 EXPORT

process_file function and most error description constants, by default.
list_files_in_archive and %donotprocess explicitly.

=head1 AUTHOR

Nikos Vaggalis <F<nikos.vaggalis@gmail.com>>

For a complete application based on the module look at :
L<http://sourceforge.net/projects/unrarextractrec/>


=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009,2010 by Nikos Vaggalis

This library and all of its earlier versions are licenced under GPL3.0

=cut
