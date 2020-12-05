from pwn import *

elf = ELF('ret2libc2')
io = process(elf.path)


