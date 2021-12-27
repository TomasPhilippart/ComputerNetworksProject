#ifndef USER_API_H
#define USER_API_H

extern char *server_ip;
extern int server_port;

int startup();
int validate_dns(char *name);

#endif
