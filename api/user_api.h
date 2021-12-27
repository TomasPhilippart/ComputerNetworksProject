#ifndef USER_API_H
#define USER_API_H

/* status codes */
#define STATUS_OK 2
#define STATUS_NOK 3
#define STATUS_DUP 4

#define FAIL 0
#define SUCCESS 1

#define MAX_LINE_SIZE 300
#define MAX_ARG_SIZE 250


int setup();
int validate_hostname(char *name);
int validate_ip(char *ip_addr);
int validate_port(char *port);
void end_session();

// User registration management
int register_user(char *user, char *pass);
int unregister_user(char *user, char *pass);

// User access management
int login(char *user, char *pass);

// UDP protocol functions
int send_message_udp(char *message);
int rcv_message_udp(char *buffer);

#endif
