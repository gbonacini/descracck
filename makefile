OPTS = -O3 -I. --std c++20  -arch=sm_86

all: descracker

des.o: des.cu descuda.hpp desdata.h
	nvcc -c $(OPTS)   -o $@ $<

parseCmdLine.o : parseCmdLine.cpp parseCmdLine.hpp
	nvcc -c $(OPTS)   -o $@ $<

descracker.o: descracker.cu
	nvcc -c $(OPTS)   -o $@  $<

descracker: descracker.o des.o parseCmdLine.o
	nvcc $(OPTS)   -o $@  $?

clean:
	rm -f *.o descracker

install:
	install --target-directory /usr/local/bin descracker 

uninstall:
	rm -f /usr/local/bin/descracker
