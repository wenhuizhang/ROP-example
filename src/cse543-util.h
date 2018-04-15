
/* Defines */
#define FILE_CLEAR 1
#define FILE_APPEND 0

extern int buffer_from_file(char *filepath, unsigned char **buf);
extern int write_to_file(char *fname, char *content, int len, unsigned flag);
extern int errorMessage( char *msg );
