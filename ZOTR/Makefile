objects = test.o timing.o ZOTR.o
DEFINES = -DPIPE=$(p)
CC = icpc -xHost -O3 $(DEFINES)

ZOTR_Timing_p$(p) : main.cpp ZOTR.cpp timing.cpp
	$(CC) -c ZOTR.cpp -o ZOTR.o
	$(CC) -c timing.cpp ZOTR.o -o timing.o
	$(CC) -c test.cpp ZOTR.o -o test.o
	$(CC) main.cpp test.o timing.o ZOTR.o -o ZOTR_Timing_p$(p)
	make clean


clean:
	rm $(objects)