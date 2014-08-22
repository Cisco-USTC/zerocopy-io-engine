#! /bin/sh
#set -x
cd driver
make clean && make
cd ../lib
make clean && make
cd ../samples/echo
make clean && make
cd ../list_devices/
make clean && make
cd ../packet_generator
make clean && make
cd ../packet_generator_modify
make clean && make
cd ../packet_generator_single
make clean && make
cd ../packet_generator_thread
make clean && make
cd ../rxdump
make clean && make
cd ../trace_generator
make clean && make
cd ../forwarding
make clean && make
cd ../mini_forwarding
make clean && make
cd ../bare_fifo
make clean && make
cd ../list_devices
./list_devices
