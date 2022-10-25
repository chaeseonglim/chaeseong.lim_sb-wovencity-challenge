#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <assert.h>
#include "include/secureboot.h"

int main(int argc, char *argv[])
{
    uint8_t tmpbuf[TMPBUF_SZ];
    int rc = 0;
    
    if ( argc != 2 ){
        perror("wrong arguments");
        exit(VERIFY_GENERIC_ERROR);
    } 
    
    FILE *in_file = fopen(argv[1], "rb");
    if ( !in_file ){
        perror("fopen");
        exit(VERIFY_GENERIC_ERROR);
    }

    struct stat sb;
    if ( stat(argv[1], &sb) == -1 ){
        perror("stat");
        exit(VERIFY_GENERIC_ERROR);
    }

    uint8_t *file_content = malloc(sb.st_size);
    if ( file_content == NULL ) {
        perror("malloc");
        exit(VERIFY_GENERIC_ERROR);
    }

    fread(file_content, sb.st_size , 1, in_file);

    /* perform the verification */
    rc = secureboot_validate_image(file_content, tmpbuf, TMPBUF_SZ);

    assert( rc == VERIFY_SUCCESS);
    
    /* clean and exit */
    free(file_content);
    fclose(in_file);
    return VERIFY_SUCCESS;
}