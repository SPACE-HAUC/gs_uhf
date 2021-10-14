CC = gcc
CXX = g++
CPPOBJS = src/main.o src/gs_uhf.o network/network.o
COBJS = gpiodev/gpiodev.o
CXXFLAGS = -I ./ -I ./include/ -I ./network/ -Wall -pthread -DGSNID=\"roofuhf\" -Wno-format
EDLDFLAGS := -lsi446x -lpthread -lm
TARGET = roof_uhf.out

all: $(COBJS) $(CPPOBJS)
	$(CXX) $(CXXFLAGS) $(COBJS) $(CPPOBJS) -o $(TARGET) $(EDLDFLAGS)
	sudo ./$(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $<

%.o: %.c
	$(CC) $(CXXFLAGS) -o $@ -c $<

.PHONY: clean

clean:
	$(RM) *.out
	$(RM) *.o
	$(RM) src/*.o
	$(RM) network/*.o