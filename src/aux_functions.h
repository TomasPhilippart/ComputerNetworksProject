#ifndef AUX_FUNCTIONS_H
#define AUX_FUNCTIONS_H

int check_pass(char *pass);
int check_uid(char *uid);
int check_gid(char *gid);
int check_mid(char *gid);
int check_filename(char *filename);
int check_group_name(char *group_name);

int parse_regex(char *str, char *regex);

#endif