CC   = gcc

# A phony target is one that is not really the name of a file
# https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: all clean run

all: user

user: user.o api/user_api.o
	gcc -o user user.o api/user_api.o
	
user.o: user.c api/user_api.h
	gcc -o user.o -c user.c

api/user_api.o: api/user_api.c
	gcc -o api/user_api.o -c api/user_api.c

clean:
	@echo Cleaning...
	rm -f fs/*.o *.o user