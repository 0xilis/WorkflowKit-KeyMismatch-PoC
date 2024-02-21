#import <Foundation/Foundation.h>

/*
 * Snoolie K, (c) 2024.
 * Taken from by WIP shortcuts-sign CLI tool.
 * Awful code, but works, and doesn't depend
 * on needing Apple Archive linked!
*/

char *archive;
size_t archive_size;

void load_file_into_memory(const char *restrict filepath) {
 FILE *fp = fopen(filepath, "r");
 if (!fp) {
  fprintf(stderr,"shortcuts-sign: failed to open file\n");
  exit(1);
 }
 fseek(fp, 0, SEEK_END);
 size_t size = ftell(fp);
 fseek(fp, 0, SEEK_SET);
 archive = malloc(size * sizeof(char));
 /* copy bytes to binary */
 int c;
 size_t n = 0;
 while ((c = fgetc(fp)) != EOF) {
  archive[n++] = (char) c;
 }
 archive_size = n;
 fclose(fp);
}

NSData *auth_data_from_path(char *filepath) {
 /* load .shortcut file into memory */
 load_file_into_memory(filepath);
 /* find the size of AEA_CONTEXT_FIELD_AUTH_DATA field blob */
 /* We assume it's located at 0x8-0xB */
 register const char *sptr = archive + 0xB;
 size_t buf_size = *sptr << 24;
 buf_size += *(sptr - 1) << 16;
 buf_size += *(sptr - 2) << 8;
 buf_size += *(sptr - 3);
 printf("got buffer size (%zu)\n",buf_size);
 /* we got buf_size, now fill buffer */
 uint8_t *buffer = (uint8_t *)malloc(buf_size);
 /*
  * the reason why we are doing a reverse
  * iteration is because doing it this way
  * will allow arm devices to take advantage
  * of the cbnz instruction, which should
  * mean about a 2 cycle save per iteration.
  *
  * also we're going to blindly trust that buf_size
  * is not larger than the buffer, because unless
  * you malform a aea file it should never be.
 */
 unsigned int i = buf_size;
 fill_buffer:
 i--;
 buffer[i] = archive[i+0xc];
 if (i != 0) {goto fill_buffer;};
 printf("filled buffer\n");
 /* make buffer NSData */
 NSData *authData = [NSData dataWithBytesNoCopy:buffer length:buf_size];
 return authData;
}