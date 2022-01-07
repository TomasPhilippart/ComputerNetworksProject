#ifndef CONSTANTS_H
#define CONSTANTS_H

#define TRUE 1
#define FALSE 0

/* sizes */
#define GIANT_SIZE 4000
#define UID_SIZE 5
#define PASSWORD_SIZE 8
#define GID_SIZE 2
#define MAX_GNAME 24
#define MAX_TSIZE 240
#define MID_SIZE 4
#define MAX_FNAME 24
#define MAX_FSIZE 10
#define EXTENSION_SIZE 3
#define COMMAND_SIZE 3
#define MAX_STATUS_SIZE 3

/* status codes */
#define STATUS_OK 2
#define STATUS_NOK 3
#define STATUS_DUP 4
#define STATUS_NOGROUPS 5
#define STATUS_NEW_GROUP 6
#define STATUS_USR_INVALID 7
#define STATUS_GID_INVALID 8
#define STATUS_GNAME_INVALID 9
#define STATUS_GROUPS_FULL 10
#define STATUS_EOF 11
#define STATUS_ERR 12

#define MAX_LINE_SIZE 300
#define MAX_ARG_SIZE 250

#endif