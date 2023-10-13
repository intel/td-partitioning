#!/bin/bash

rm vsyscall_test
gcc -static vsyscall_test.c -o vsyscall_test
