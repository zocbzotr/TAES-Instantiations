/** @file timing.h
 */
#ifndef TIMING_H__
#define TIMING_H__
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include "ThetaCB3.h"

#ifdef _MSC_VER
unsigned long CurrentProcessorNumber(void);
__inline unsigned long long read_tsc(void);
#endif

#ifdef __GNUC__
inline unsigned long long read_tsc(void);
#endif

void setCPUaffinity();

void block_rndfill(unsigned char *buf, const int len);

int time_base(double *av, double *sig);

int time_enc16(double *av, double *sig, unsigned int k_len, unsigned long long dataLengthInBytes, unsigned long long AdataLengthInBytes);

double enc_cycles(unsigned int k_len, unsigned long long dataLengthInBytes, unsigned long long AdataLengthInBytes);

void timing();

#endif  //TIMING_H__