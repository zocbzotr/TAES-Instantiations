objects = test.o timing.o ThetaCB3.o
DEFINES = -DPIPE=$(p)
CC = icpc -xHost -O3 $(DEFINES)

ThetaCB3_Timing_p$(p) : main.cpp ThetaCB3.cpp timing.cpp
	$(CC) -c ThetaCB3.cpp -o ThetaCB3.o
	$(CC) -c timing.cpp ThetaCB3.o -o timing.o
	$(CC) -c test.cpp ThetaCB3.o -o test.o
	$(CC) main.cpp test.o timing.o ThetaCB3.o -o ThetaCB3_Timing_p$(p)
	make clean


clean:
	rm $(objects)