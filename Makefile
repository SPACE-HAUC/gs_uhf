CXX = g++
CPPOBJS = src/main.o src/gs_uhf.o src/network.o
COBJS = uhf_modem/uhf_modem.o
CXXFLAGS = -I ./include/ -I ./uhf_modem/ -Wall -pthread
TARGET = roof_uhf.out

all: $(COBJS) $(CPPOBJS)
	$(CXX) $(CXXFLAGS) $(COBJS) $(CPPOBJS) -o $(TARGET)
	./$(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $<

%.o: %.c
	$(CXX) $(CXXFLAGS) -o $@ -c $<

.PHONY: clean

clean:
	$(RM) *.out
	$(RM) *.o
	$(RM) src/*.o