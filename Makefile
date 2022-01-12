
CC= gcc
ARGS= -Wall -O1
SRC= ./src
BUILD= ./build

default: pe_interface.o
	${CC} ${ARGS} -o perser ${BUILD}/pe_interface.o ${SRC}/main.c

pe_interface.o:
	${CC} ${ARGS} -c ${SRC}/pe_interface.c -o ${BUILD}/pe_interface.o

format:
	astyle --style=allman --indent=spaces=2 --max-code-length=65 *.c
	rm *.orig 

clean:
	rm -rf perser ${BUILD}/*.o