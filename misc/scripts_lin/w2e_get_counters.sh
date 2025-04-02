#!/bin/bash

# Parses shmm counters and prints in decimal. '-e' reverts byte order.
# Refer to w2e_ctrs_t declaration.

# Example output:
# Wed Apr  2 22:29:02 UTC 2025
# 58699
# 58651
# 0
# 0
# 48
# 0
# 22073
# 19119


# Timestamp 64-bit
xxd -c 8 -g 8 -l 8 -e /tmp/.w2e_ctrs_shmm.bin | awk '{printf "%d\n", "0x" $2}' | date

# All subsequent fields (32-bit)
xxd -c 4 -g 4 -s 8 -e /tmp/.w2e_ctrs_shmm.bin | awk '{printf "%d\n", "0x" $2}'
