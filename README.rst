lyn — Python bindings for GNU Lightning
=======================================

Lyn provides Python bindings for GNU Lightning, the light-weight just-in-time
(JIT) compiler that translates to native machine code.

The code is hosted on https://github.com/cslarsen/lyn/ and is installable from
https://pypi.python.org/pypi/lyn/.

"Lyn" is the Norwegian word for "lightning".

**NOTE:** This project is currently in extremely early stages!

Status
------

As mentioned above, Lyn is fledgling: I've just spent a few hours on it, so
almost nothing is supported and — in particular — I've only targeted x86-64
opcodes just yet. Some tests are also failing: Min and max 64-bit numbers don't
seem to pass through correctly, so I'm currently working on fixing that issue
first.

In spite of this, I've managed to create a *really* simple program in Python
that is JIT-compiled to native x86-64 machine code: A glorious function that
returns the value of 123! Here's the code::

    from lyn import Lightning, Register

    with Lightning().state() as jit:
        jit.prolog()

        # Actual code
        jit.movi(Register.v0, 123)
        jit.retr(Register.v0)

        # Compile to native code and wrap in a Python-callable function
        func = jit.emit_function(Lightning.word_t)

        print("Function returned %s and that is %s!" % (
            func(), "correct" if func() == 123 else "incorrect"))

Also, I've not been able to compile GNU Lightning with disassembly support, so
I just used Capstone instead (install with ``pip install capstone``)::

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
    length = (jit.address(end) - jit.address(start)).value
    codebuf = ctypes.create_string_buffer(length)
    ctypes.memmove(codebuf, ctypes.c_char_p(incr.address.value), length)
    print("Compiled %d bytes starting at 0x%x" % (length, incr.address))

    def hexbytes(b):
        return "".join(map(lambda x: hex(x)[2:] + " ", b))

    # Capstone is smart enough to stop at the first RET-like instruction.
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.syntax = capstone.CS_OPT_SYNTAX_ATT # Change to Intel syntax if you want
    for i in md.disasm(codebuf, incr.address.value):
        print("0x%x %-15s%s %s" % (i.address, hexbytes(i.bytes), i.mnemonic, i.op_str))

    raw = "".join(map(lambda x: "\\x%02x" % x, map(ord, codebuf)))
    print("\nRaw bytes: %s" % raw)

This outputs::

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

    Raw bytes: \x48\x83\xec\x30\x48\x89\x2c\x24[...]

I'm using ctypes for creating the bindings, which comes with some challenges:
GNU Lightning is written in C, and relies heavily on compile-time macros that
define machine specific opcodes, register values and so on.

Because of this, it would be more natural to simply create bindings through a C
extension. On the other hand, though, ctypes makes it possible to ship Lyn as a
platform independent, pure Python source. I'll chew on this for a while, and
we'll see what happens.

Installation
------------

Either::

    $ pip install lyn

or::

    $ python setup.py install

Requirements
------------

You need GNU Lightning version 2.1.0, built as a shared library.

Remember to configure GNU Lightning with the option ``--enable-shared``.  To
use the disassembler, you should also add ``--enable-disassembler``.

Author and license
------------------

Copyright (C) 2015 Christian Stigen Larsen

Distributed under the LGPL v2.1 or later. You are allowed to change the license
on a particular copy to the LGPL v3.0, the GPL v2.0 or the GPL v3.0.
