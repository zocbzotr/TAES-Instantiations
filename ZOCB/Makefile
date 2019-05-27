objects = test.o timing.o ZOCB.o
DEFINES = -DPIPE=$(p)
CC = icpc -xHost -O3 $(DEFINES)

ZOCB_Timing_p$(p) : main.cpp ZOCB.cpp timing.cpp
	$(CC) -c ZOCB.cpp -o ZOCB.o
	$(CC) -c timing.cpp ZOCB.o -o timing.o
	$(CC) -c test.cpp ZOCB.o -o test.o
	$(CC) main.cpp test.o timing.o ZOCB.o -o ZOCB_Timing_p$(p)
	make clean


clean:
	rm $(objects)