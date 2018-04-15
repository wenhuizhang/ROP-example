#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <fcntl.h>
#include "cse543-util.h"

int buffer_from_file(char *filepath, unsigned char **buf)
{
  int err;
  struct stat *statbuf;
  FILE *fptr;
  size_t filesize;

  statbuf = (struct stat *)malloc(sizeof(struct stat));
  assert( statbuf != NULL );

  err = stat( filepath, statbuf );

  /* if file does not exist ... */
  if ( err != 0 ) {
    filesize = 0;
  }
  /* if file is there but empty */
  else if (!( filesize = statbuf->st_size ));
  /* else if file exists */
  else {
    /* Get file size */
    assert( filesize > 0 );

    /* Read file data into buf */
    *buf = (unsigned char *)malloc(filesize); 
    assert( *buf != NULL );
  
    fptr = fopen( filepath, "r" );
    if ( fptr != NULL ) {
      err = fread( *buf, 1, filesize, fptr );
      assert( err == filesize ); 
    }
    fclose( fptr );
  }

  free( statbuf );
  
  return filesize;
}


int write_to_file(char *fname, char *content, int len, unsigned flag )
{
	int fh;
	int outbytes;
	unsigned flag_set = ((flag == FILE_CLEAR) ? 
			     (O_RDWR | O_TRUNC | O_CREAT) :
			     (O_RDWR | O_APPEND));

	if ( (fh=open(fname, flag_set, S_IRUSR | S_IWUSR)) == -1 )
	{
		/* Complain, explain */
		char msg[128];
		sprintf( msg, "failure opening file [%.64s]\n", fname );
		errorMessage( msg );
		return -1;
	}

	outbytes = write( fh, content, len );

	if ( outbytes != len ) {
		/* Complain, explain */
		char msg[128];
		sprintf( msg, "failure writing to file [%.64s]\n", fname );
		errorMessage( msg );
		return -1;
	}

	return 0;
}


int errorMessage( char *msg ) 
{
	/* Print message and return */
	fprintf( stderr, "CSE443 Error: %s\n", msg );
	return( 0 );
}
