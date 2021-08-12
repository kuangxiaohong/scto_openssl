
PWD=$(shell pwd)
all:
	gcc -g test.c -I${PWD}/ -o test -ldl -lpthread -lcrypto ${PWD}/../dep_lib/libteec.a
clean:
	rm -rf *.o test
