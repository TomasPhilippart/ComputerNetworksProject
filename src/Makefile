# A phony target is one that is not really the name of a file
# https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: all clean run

all: user

user: client/user.o client/api/user_api.o
	gcc -o user client/user.o client/api/user_api.o -g
	
user.o: client/user.c client/api/user_api.h
	gcc -o client/user.o -c client/user.c -g

api/user_api.o: client/api/user_api.c
	gcc -o client/api/user_api.o -c client/api/user_api.c -g

clean:
	@echo Cleaning...
	rm -f client/api/*.o client/*.o user