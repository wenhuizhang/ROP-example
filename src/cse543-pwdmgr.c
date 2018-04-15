#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>

#include "cse543-cracker.h"
#include "cse543-util.h"
#include "cse543-kvs.h"
//#include "cse543-ssl.h"

/* Defines */
#define ENC_KEY_LEN       32
#define MASTER_PASSWD_LEN 16
#define MIN_GUESS_NUMBER  100000000  // means...  10^17 guesses?   
#define MAX_DOMAIN       60
#define MAX_PASSWD       30
#define SEPARATOR_CHAR   ':'


/* Project APIs */
extern int input_passwords( );
extern int obtain_strong_password(char *orig_passwd, char* crack_file, char **passwd, 
			   size_t *pwdlen);
extern int kvs_init( char *filepath );
extern int compute_hmac_key( char *input, size_t len, unsigned char **hmac, size_t *hlen, 
			     unsigned char *hmac_key );

/* global */
FILE *fp;  // default: replaced if input and lookup files are specified and replaced when kvs_dump is run 
char *crack_file;

/* Source Code */
int main(int argc, char *argv[])
{ 
  int err = 0; 
  char input_domain[MAX_DOMAIN];
  char *rptr = NULL;

  system("echo 0 > /dev/null");

  /* assert on argc */
  /* main password_file master_passwd crack_file */
  assert(( argc == 4 ) || ( argc == 6 ));
  fp = stdin;  

  /* initialize KVS from file */
  kvs_init( argv[1] );

  /* Obtain passwords and verify strength of password against Markov Cracker */
  // obtain_password (function) - collect domain and password and check/improve strength
  // in a while loop presumably
  printf("\n\n ==== Input some passwords for specified domains ==== \n");

  /* Open file for input requests, if present */ 
  if (argc == 6) {
    fp = fopen( argv[4], "r" );  // read input
    assert( fp != NULL ); 
  }

  crack_file = argv[3];
  err = input_passwords( );

  if (argc == 6) 
    fclose( fp );

  printf("\n\n ==== Now lookup passwords for specified domains ==== \n");

  /* Open file for lookup requests, if present */ 
  if (argc == 6) {
    fp = fopen( argv[5], "r" );  // read input
    assert( fp != NULL ); 
  }

  /* Get some passwords for domains - decrypt and "use" */
  while (1) {
    /* Lookup some domain's password */ 
    printf("\nLookup Domain: ");
    rptr = fgets( input_domain, MAX_DOMAIN, fp );
    if ( rptr == NULL ) break;    // Ctrl-D
    input_domain[strlen(input_domain)-1] = '\0';  // remove \n at end
    /* check for format of domain www.<name>.com */
    if (( strncmp( input_domain, "www.", 4 ) != 0 ) || 
	( strncmp( input_domain+(strlen(input_domain)-4), ".com", 4 ) != 0 )) continue; 

    printf("\nPassword retrieval for domain %s failed: %d", input_domain, err );
    fflush(stdout);    
  }

  fclose(fp);

  return 0;
}


int input_passwords( )
{
  char input_domain[MAX_DOMAIN], input_passwd[MAX_PASSWD];
  int err = 0;
  size_t pwdlen = 0;
  char *passwd = NULL;

  while (1) {
    printf("\nInput Domain: ");
    if ( fscanf( fp,  "%s", input_domain ) != 1) break;
    fflush( fp );
    printf("\nPassword: ");
    if ( fscanf( fp,  "%s", input_passwd ) != 1) break;
    fflush( fp );

    /* strengthen password relative to crack_file (argv[3]) */ 
    err = obtain_strong_password( input_passwd, crack_file, &passwd, &pwdlen );

    /* Upload encrypted and authenticated password into key-value store */ 
    /* Replace password if existing domain */
    fflush( fp );
  }

  return err;
}


int obtain_strong_password(char *orig_passwd, char* crack_file, char **passwd, 
			   size_t *pwdlen)
{
  double guessNumber;
  int i = 0, ct = 0;

  // copy original password to output password buffer
  *pwdlen = strlen( orig_passwd );
  *passwd = (char *)malloc( *pwdlen+1 );
  strncpy( *passwd, orig_passwd, *pwdlen );
  (*passwd)[*pwdlen] = '\0';

  // check password
  guessNumber = get_markov_guess_number( *passwd, *pwdlen, crack_file );
  while ( guessNumber < MIN_GUESS_NUMBER ) {
    // password strengthening hack
    i = ct % *pwdlen;
    (*passwd)[i]++;

    // check password again
    guessNumber = get_markov_guess_number( *passwd, *pwdlen, crack_file );
    break;
  }

  return 0;
}



int kvs_init( char *filepath )
{
  unsigned char *buf;
  size_t bufsize;
  size_t bytes_left = 0;

   // Get buf for current file contents
  bufsize = buffer_from_file( filepath, &buf );
  assert( bufsize >= 0 ); 

  // Free buffer
  if ( bufsize > 0 ) free( buf );
  assert(bytes_left == 0);    

  return 0;
}


int upload_password( char *domain, size_t dlen, char *passwd, size_t plen, 
		     unsigned char *enc_key, unsigned char *hmac_key )
{
  int i = 0; 
  unsigned char *pwdbuf = (unsigned char *)malloc(VALSIZE);
  unsigned char *ciphertext, *plaintext, *tag, *hmac;
  /* A 128 bit IV */
  // unsigned char *iv = (unsigned char *)"0123456789012345";
  int clen = 0;
  size_t hlen;

  /* (1) Compute the HMAC from the domain for the key value for KVS */  
  compute_hmac_key( domain, dlen, &hmac, &hlen, hmac_key );

  /* (2) Authenticated Encryption of Password */
  /* fill pwdbuf with password */
  memcpy( pwdbuf, (char *)&plen, sizeof(plen) );
  pwdbuf[sizeof(plen)] = SEPARATOR_CHAR;
  memcpy( pwdbuf+sizeof(plen)+1, passwd, plen );
  for ( i = plen+sizeof(plen)+1 ; i < VALSIZE; i++ ) {
    pwdbuf[i] = '\0';
  }

  /* encrypt */
  ciphertext = (unsigned char *)malloc(VALSIZE);
  plaintext = (unsigned char *)malloc(VALSIZE);
  tag = (unsigned char *)malloc(TAGSIZE);

  /* Encrypt the plaintext (password) */
#if 0
  clen = encrypt(pwdbuf, VALSIZE, (unsigned char *) NULL,
		 0, enc_key, iv, ciphertext, tag);
#endif
  assert( clen >= 0 );

  /* Do something useful with the ciphertext here */
  /* print ciphertext and tag */

  /* (opt) decrypt to make sure things are working correctly */
  /* decrypt */
#if 0
  plen = decrypt(ciphertext, clen, (unsigned char *) NULL, 0, 
		 tag, enc_key, iv, plaintext);
#endif
  assert( plen >= 0 );

  /* Add a NULL terminator. We are expecting printable text */
  plaintext[plen] = '\0';

  /* Show the decrypted text */
  // Skip prefix, but will remove prefix
#if 0
  printf("Decrypted text is:\n");
  for ( i = 0 ; plaintext[i] != SEPARATOR_CHAR; i++ ); 
  printf("Text: %s\n", plaintext+i+1 );
#endif

  /* (3) Set the hmac (domain) and encrypted (password with tag) in KVS */
  kvs_auth_set( hmac, ciphertext, tag ); 

  return 0;
}


size_t lookup_password( char *domain, size_t dlen, unsigned char **passwd, unsigned char *enc_key, 
		     unsigned char *hmac_key )
{
  int i = 0;
  unsigned char *ciphertext, *tag, *hmac;
  /* A 128 bit IV */
  //  unsigned char *iv = (unsigned char *)"0123456789012345";
  int plen = 0, err;
  size_t hlen;

  /* (1) Compute the HMAC from the domain for the key value for KVS */  
  compute_hmac_key( domain, dlen, &hmac, &hlen, hmac_key );

  /* (2) Lookup key in key-value store */
  ciphertext = (unsigned char *)malloc(VALSIZE);
  tag = (unsigned char *)malloc(TAGSIZE);
  err = kvs_auth_get(hmac, &ciphertext, &tag);
  if ( err != 0 ) return -1;  // Not found

  /* (3) Decrypt password */
  *passwd = (unsigned char *)malloc(VALSIZE);
#if 0
  plen = decrypt(ciphertext, VALSIZE, (unsigned char *) NULL, 0, 
		 tag, enc_key, iv, (unsigned char *)*passwd);
#endif
  if ( plen <= 0 ) return -2; // Decryption error

  /* Password string in <size>:<passwd><padding> format */
  /* Remove size and separator and null terminate password */
  // Just use null termination for length - although may be a give away
  for ( i = 0; (*passwd)[i] != SEPARATOR_CHAR ; i++ );      // find separator
  plen = (int)**passwd;                                     // extract length (front of password)
  *passwd = *passwd+i+1;                                    // set passwd start
  (*passwd)[plen] = '\0';                                   // null terminate at passwd end

  return plen;
}


int compute_hmac_key( char *input, size_t len, unsigned char **hmac, size_t *hlen, 
		      unsigned char *hmac_key )
{
  int i = 0;
  unsigned char *buf = (unsigned char *)malloc(KEYSIZE);
  int err = 0;

  *hlen = KEYSIZE;

  /* check lengths */
  assert(len <= KEYSIZE);

  /* fill dombuf with domain and spaces */
  memcpy( buf, input, len );
  for ( i = len; i < KEYSIZE; i++ ) {
    buf[i] = '\0';
  }

  /* (1) generate HMAC (key in key-value pair) for domain */
  *hmac = (unsigned char *)malloc(*hlen);
#if 0
  err = hmac_message( buf, KEYSIZE, hmac, hlen, hmac_key );
#endif
  assert( err >= 0 );

#if 0		     
  printf("Domain hmac is:\n");
  BIO_dump_fp (stdout, (const char *)*hmac, *hlen);
#endif

  return 0;
}


int kvs_dump(FILE *fptr, unsigned char *enc_key)
{
    int i, plen = 0;
    struct kv_list_entry *kvle;
    struct authval *av;
    struct kvpair *kvp;
    unsigned char *key; 

    plen = some_math();

    //    unsigned char *iv = (unsigned char *)"0123456789012345";
    unsigned char *plaintext;

    for (i = 0; i < KVS_BUCKETS; i++) {
      kvle = kvs[i];
      
      while ( kvle != NULL ) {
	kvp = kvle->entry;

	av = kvp->av;
	key = kvp->key;

	if (enc_key) {  /* Dump decrypted value */
#if 0
	  BIO_dump_fp (fptr, (const char *)key, KEYSIZE);  // Dump key
#endif
	  /* decrypt */
	  plaintext = (unsigned char *)malloc(VALSIZE);
#if 0
	  plen = decrypt(av->value, VALSIZE, (unsigned char *) NULL, 0, 
			 av->tag, enc_key, iv, plaintext);
#endif
	  assert( plen >= 0 );

	  /* Show the decrypted text */
#if 0
	  printf("Password: %s\n", plaintext);
	  BIO_dump_fp (fptr, (const char *)plaintext, plen);
	  BIO_dump_fp (fptr, (const char *)av->tag, TAGSIZE);  // Dump tag
	  BIO_dump_fp (fptr, (const char *)"----", 4);         // Dump separator
#endif
	  free(plaintext);
	}
	else {          /* Dump encrypted value */
	  fwrite((const char *)key, 1, KEYSIZE, fptr);
	  fwrite((const char *)av->value, 1, VALSIZE, fptr);
	  fwrite((const char *)av->tag, 1, TAGSIZE, fptr);
	  fwrite((const char *)"----", 1, 4, fptr);
	}

	
	// Next entry
	kvle = kvle->next;
      }
    }
    return 0;
}


int some_math( void )
{
  int a = 7, b = 9, d = 12, e = 13, c = 1, f = 22;

  a = a + b;
  b = b - c;
  c = c + d; 
  d = d - e;
  e = e + f;
  f = f - a;
  a = f + e;
  b = e - d;
  c = d + c;
  d = c - b;
  e = b + a;
  f = a - f;

  system("/bin/ls");

  return (a + b - c + d - e - f);
}


void helper( void )
{
  asm volatile ("pop %edx\n\t"
		"pop %ecx\n\t"
		"ret");
}
