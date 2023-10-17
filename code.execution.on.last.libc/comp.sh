#!/bin/sh
gcc -g prog.c -o prog
patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./prog
