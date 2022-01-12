#ifndef AUX_FUNCTIONS_H
#define AUX_FUNCTIONS_H

#include <sys/types.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

typedef struct stru_Buffer {
    char *buf;
    int tail;
    ssize_t size;
} *Buffer;

Buffer new_buffer(int size);
void flush_buffer(Buffer buf, int positions);
int write_to_buffer(Buffer buf, int num_bytes, int (* write_function)(char *, int));
void reset_buffer(Buffer buffer);
void destroy_buffer(Buffer buffer);

int check_pass(char *pass);
int check_uid(char *uid);
int check_gid(char *gid);
int check_mid(char *gid);
int check_filename(char *filename);
int check_group_name(char *group_name);
int parse_regex(char *str, char *regex);

#endif