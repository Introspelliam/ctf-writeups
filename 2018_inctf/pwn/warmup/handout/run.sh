#!/bin/bash
unset LD_LIBRARY_PATH
qemu-arm -L ./ ./wARMup
#qemu-arm -g 1234 -L ./ ./wARMup

