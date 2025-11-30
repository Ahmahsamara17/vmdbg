#!/usr/bin/env python3
from pwn import *

p = process(["./boat_vm", "float_program.bin"])


p.interactive()
