# ----------- zzPwn Header Start -----------
from pwn import *
from zzPwnlib import *
from LibcSearcher import *
context(os='linux', arch='amd64', log_level='debug')

elf_path    = './xctf_pwn_***_****'
elf         = ELF(elf_path)
io          = process(elf_path)
#io          = remote('111.200.241.244',64223)
# ----------- zzPwn Header End -------------