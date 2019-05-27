#! /bin/bash
source /opt/intel2019/parallel_studio_xe_2019/psxevars.sh intel64
source /opt/intel2019/compilers_and_libraries/linux/mpi/intel64/bin/mpivars.sh intel64
source /opt/intel2019/ipp/bin/ippvars.sh intel64
export CPATH=$CPATH:/opt/intel2019/include:/opt/intel2019/compilers_and_libraries/linux/mpi/intel64/include:/opt/intel2019/ipp/include:/usr/include
export INCLUDE=$INCLUDE:/opt/intel2019/include:/opt/intel2019/compilers_and_libraries/linux/mpi/intel64/include:/opt/intel2019/ipp/include:/usr/include

cd ./ZOCB
make p=4
cd -
cd ./ZOTR
make p=4
cd -
cd ./ThetaCB3
make p=4
cd -