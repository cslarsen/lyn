#!/usr/bin/env python

"""
Example using Lyn (bindings to GNU Lightning) to JIT-compile native code that
takes an integer and returns its increment.

Then we disassemble the function using Capstone. Sweet!

Note that we explicitly disassemble the code as x86-64. If you're on a
different architecture, just pass different arguments to capstone.Cs.

Example output:

    Compiled 34 bytes starting at 0x10acf4000
    0x10acf4000 48 83 ec 30    subq $0x30, %rsp
    0x10acf4004 48 89 2c 24    movq %rbp, (%rsp)
    0x10acf4008 48 89 e5       movq %rsp, %rbp
    0x10acf400b 48 83 ec 18    subq $0x18, %rsp
    0x10acf400f 48 89 f8       movq %rdi, %rax
    0x10acf4012 48 83 c0 1     addq $1, %rax
    0x10acf4016 48 89 ec       movq %rbp, %rsp
    0x10acf4019 48 8b 2c 24    movq (%rsp), %rbp
    0x10acf401d 48 83 c4 30    addq $0x30, %rsp
    0x10acf4021 c3             retq

    Raw bytes:
        \x48\x83\xec\x30\x48\x89\x2c\x24
        ...

For this to work, you need the GNU Lightning shared library (liblightning.*) in
the library search path. You also need Capstone, which you can get from PyPi.

2015-08-23 Christian Stigen Larsen
"""

from lyn import *
import capstone
import ctypes

def hexbytes(b):
    return "".join(map(lambda x: hex(x)[2:] + " ", b))

def chunkstring(string, length):
    # Taken from http://stackoverflow.com/a/18854817/21028
    return (string[0+i:length+i] for i in range(0, len(string), length))

lib = Lightning()
jit = lib.state()

# A function that returns one more than its integer input
start = jit.note()
jit.prolog()
arg = jit.arg()
jit.getarg(R0, arg)
jit.addi(R0, R0, 1)
jit.retr(R0)
jit.epilog()
end = jit.note()

# Bind foreign function
incr = jit.emit_function(word_t, [word_t])

# Sanity check
assert(incr(1234) == 1235)

# This part should be obvious to C programmers: We need to read data from raw
# memory in to a Python iterable.
length = (jit.address(end) - jit.address(start)).value
codebuf = ctypes.create_string_buffer(length)
ctypes.memmove(codebuf, ctypes.c_char_p(incr.address.value), length)
print("Compiled %d bytes starting at 0x%x" % (length, incr.address))

# Capstone is smart enough to stop at the first RET-like instruction.
# (But, obviously, not enough to guess it's host architecture)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# Change to Intel syntax, if you want
md.syntax = capstone.CS_OPT_SYNTAX_ATT

# Print native instructions
for i in md.disasm(codebuf, incr.address.value):
    print("0x%x %-15s%s %s" % (i.address, hexbytes(i.bytes), i.mnemonic, i.op_str))

# ... and its raw bytes
print("\nRaw bytes:")
raw = "".join(map(lambda x: "\\x%02x" % x, map(ord, codebuf)))
for line in chunkstring(raw, 8*4):
    print("    %s" % line)

jit.release()
lib.release()
