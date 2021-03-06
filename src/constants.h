#ifndef CONSTANTS_H
#define CONSTANTS_H

#define TRUE 1
#define FALSE 0

#define STATUS_FAIL -1
#define SUCCESS 0

/* sizes */
/* All constants pertraining to tokens
   given by input are all incremented by 1 */
#define MAX_BUF_SIZE 4096
#define MAX_PORT_SIZE 5
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
#define MAX_NUM_MSG_DIGITS 4

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

#define MAX_LINE_SIZE 300        /* Maximum input size accepted from the user */
#define MAX_ARG_SIZE 25          /* Maximum non-text token size */

/* for setting input size while scanning buffers */
#define STR2(x) #x			
#define STR(X) STR2(X)

/* Expressions to match the format (need to check other aspects such being non zero afterwards) */
#define GNAME_EXP "[a-zA-Z0-9_-]{1," STR(MAX_GNAME) "}"
#define UID_EXP "[0-9]{" STR(UID_SIZE) "}"
#define MID_EXP "[0-9]{" STR(MID_SIZE) "}"

#endif