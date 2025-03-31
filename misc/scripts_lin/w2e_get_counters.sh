#!/bin/bash

# Parses shmm counters and prints in decimal. Reverts byte order.
# Refer to w2e_ctrs_t declaration.
#
# -s 8 -- Cut off 64-bit timestamp

xxd -c 4 -g 1 -s 8 /tmp/.w2e_ctrs_shmm.bin | awk '{print $5 $4 $3 $2}' | awk '{printf "%d\n", "0x" $1}'
