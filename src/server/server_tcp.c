#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    printf("running tcp with port %s and %s\n", argv[1], atoi(argv[2]) ? "Verbose" : "Non-verbose");
    return 0;
}