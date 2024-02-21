#import <Foundation/Foundation.h>

/*
 * Snoolie K, (c) 2024.
 * Taken from by WIP shortcuts-sign CLI tool.
 * Awful code, but works, and doesn't depend
 * on needing Apple Archive linked!
*/

void load_signed_shortcut_into_memory(const char *restrict filepath);
NSData *auth_data_from_path(char *filepath);
int is_unsigned(void);
NSData *auth_data_from_archive(void);
void free_archive(void);