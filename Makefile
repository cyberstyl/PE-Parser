
CC= gcc
ARGS= -Wall -O1
SRC= ./src
BUILD= ./build

default: pe-interface.o
	${CC} ${ARGS} -o perser ${BUILD}/pe-interface.o ${SRC}/main.c

pe-interface.o:
	${CC} ${ARGS} -c ${SRC}/pe-interface.c -o ${BUILD}/pe-interface.o

format:
	astyle --style=allman --indent=spaces=2 --max-code-length=65 *.c
	rm *.orig 

clean:
	rm -rf perser ${BUILD}/*.o