#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#define PORT "58001"

int fd,errcode; 
ssize_t n;
socklen_t addrlen;
struct addrinfo hints,*res;
struct sockaddr_in addr;
char buffer[128];

int main(int argc, char **argv) {
	fd = socket(AF_INET, SOCK_DGRAM, 0); // UDP socket
	if (fd == 1) {
		exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; // IPv4
	hints.ai_socktype = SOCK_DGRAM; // UDP socket

	errcode = getaddrinfo("tejo.tecnico.ulisboa.pt", PORT, &hints, &res);
	if (errcode != 0) {
		exit(1);
	}

	//char *message = "Olá Guadiana\n";

	if (argc < 2) {
		exit(1);
	}

	n = sendto(fd, strcat(argv[1], "\n"), strlen(strcat(argv[1], "\n")), 0, res->ai_addr, res->ai_addrlen);
	if (n == -1) {
		exit(1);
	}

	addrlen = sizeof(addr);
	n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*)&addr, &addrlen);
	if (n == -1) {
		exit(1);
	}

	write(1, "echo: ", 6);
	write(1, buffer, n);

	// ...

	freeaddrinfo(res);
	close(fd);

}
