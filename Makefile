PWD=$(shell pwd)
TARGET = scto.so

CC=gcc

CFLAGS    := -g -w -Werror -fstack-protector-all -fPIC -D_GNU_SOURCE -shared -fgnu89-inline 
LIBS :=  -ldl -pthread  ${PWD}/dep_lib/libteec.a ${PWD}/dep_lib/libscto.so -lcrypto
INCDIR += -I ./ -I${PWD}/include
LDFLAGS   += $(LIBS) 
LDFLAGS   += -Wl,-z,relro,-z,now,-z,noexecstack  #safe link option
all:
	${CC} $(CFLAGS)  $(INCDIR) src/scto.c -o ./out/$(TARGET) $(LDFLAGS)
clean:
	rm -rf  out/scto.so src/*.o
