#!/usr/bin/env python

"""
Example using Lyn (bindings to GNU Lightning) to JIT-compile native code that
takes an integer and returns its increment.

Then we disassemble the function using Capstone. Sweet!

Note that we explicitly disassemble the code as x86-64. If you're on a
different architecture, just pass different arguments to capstone.Cs.

Example output:

    ompiled 34 bytes starting at 0x103b43000
    0x103b43000 sub rsp, 0x30
    0x103b43004 mov qword ptr [rsp], rbp
    0x103b43008 mov rbp, rsp
    0x103b4300b sub rsp, 0x18
    0x103b4300f mov rax, rdi
    0x103b43012 add rax, 1
    0x103b43016 mov rsp, rbp
    0x103b43019 mov rbp, qword ptr [rsp]
    0x103b4301d add rsp, 0x30
    0x103b43021 ret

For this to work, you need the GNU Lightning shared library (liblightning.*) in
the library search path. You also need Capstone, which you can get from PyPi.

2015-08-23 Christian Stigen Larsen
"""

from lyn import *
import capstone
import ctypes

lib = Lightning()
jit = lib.new_state()

# A function that returns one more than its integer input
start = jit.note()
jit.prolog()
arg = jit.arg()
jit.getarg(Register.r0, arg)
jit.addi(Register.r0, Register.r0, 1)
jit.retr(Register.r0)
jit.epilog()
end = jit.note()

# Bind function to Python: returns a word (native integer), takes a word.
incr = jit.emit_function(lib.word_t, [lib.word_t])

# Sanity check
assert(incr(1234) == 1235)

# This part should be obvious to C programmers: We need to read data from raw
# memory in to a Python iterable.
length = (jit.address(end) - jit.address(start)).ptr
codebuf = ctypes.create_string_buffer(length)
ctypes.memmove(codebuf, ctypes.c_char_p(incr.address.ptr), length)
print("Compiled %d bytes starting at 0x%x" % (length, incr.address))

# Capstone is smart enough to stop at the first RET-like instruction.
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for i in md.disasm(codebuf, incr.address.ptr):
    print("0x%x %s %s" % (i.address, i.mnemonic, i.op_str))
