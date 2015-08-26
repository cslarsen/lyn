lyn — Python bindings for GNU Lightning
=======================================

Lyn provides Python bindings for GNU Lightning::

    GNU lightning is a library that generates assembly language code at
    run-time; it is very fast, making it ideal for Just-In-Time compilers, and
    it abstracts over the target CPU, as it exposes to the clients a
    standardized RISC instruction set inspired by the MIPS and SPARC chips.

The source code is on GitHub: https://github.com/cslarsen/lyn/  
Releases are uploaded to PyPI: https://pypi.python.org/pypi/lyn/

*"Lyn"* is the Norwegian word for "lightning".

Warning
-------

This project is in early alpha! Many instructions have not been implemented
yet, and tests are lacking for those that have This means that you shouldn't be
surprised to segfault the entire Python process (you will have to get used to
that anyway, unless you happen to always write bug-free Lightning code).

But, you can use it *right now* to JIT-compile native machine code, straight
from Python. To get a taste of Lyn and GNU Lightning, scroll down to the
examples below.

Installation
------------

From PyPi::

    $ pip install lyn

From the bleeding edge::

    $ git clone https://github.com/cslarsen/lyn
    $ cd lyn
    $ python setup.py test
    $ python setup.py install

Non-Python Dependencies
-----------------------

You must install the following libraries using your favourite package manager:

    * The GNU Lightning shared library v2.1.0 (later versions may also work),
      http://www.gnu.org/software/lightning/

    * Optional: The Capstone Disassembler,
      http://www.capstone-engine.org

The last time I compiled GNU Lightning on Linux, I had to disable the
disassembly options because of linker problems with ``libopcodes.so``.  This
worked for me::

    $ ./configure --enable-shared --disable-static --disable-disassembler

To use Capstone as a disassembler with Lyn, you have to install the Python
modules and the C library.  The module can be installed with ``pip install
capstone``.

Example: Multiply two numbers
-----------------------------

In this example, we use ``with``-blocks so that the GNU Lightning environment
(along with the ``mul`` function) is reclaimed::

    from lyn import Lightning, word_t, Register

    with Lightning() as lib:
        with lib.state() as jit:
            jit.prolog()
            jit.getarg(Register.r0, jit.arg())
            jit.getarg(Register.r1, jit.arg())
            jit.mulr(Register.r0, Register.r0, Register.r1)
            jit.retr(Register.r0)
            jit.epilog()

            mul = jit.emit_function(word_t, [word_t, word_t])

            for a in xrange(-100, 100):
                for b in xrange(-100, 100):
                    assert(mul(a,b) == a*b)

To use the ``mul`` function elsewhere in your program, you need to keep a
reference to the state ``jit`` and the GNU Lightning environment ``lib``. Both
objects have ``release()`` methods for doing it manually::

    lib = Lightning()
    jit = lib.state()
    # ...
    jit.release()
    lib.release()

The last two parts are order dependant, in that ``lib.release()`` must run
after its associated states. If you *don't* release them, it's not a big deal,
but you'll waste memory. In such a case, OS will free up the memory at exit.

Example: Calling a C function
-----------------------------

This example shows how to call C functions from GNU Lightning. In the example
below, we create a function that takes a string argument and returns the result
of passing it to ``strlen``::

    import lyn
    from lyn import Register, Lightning

    lightning = Lightning()
    libc = lightning.load("c")

    jit = lightning.state()
    jit.prolog()

    # Get the Python argument
    jit.getarg(Register.r0, jit.arg())

    # Call strlen with it
    jit.pushargr(Register.r0)
    jit.finishi(libc.strlen)

    # Return strlen's return value
    jit.retval(Register.r0)
    jit.retr(Register.r0)
    jit.epilog()

    strlen = jit.emit_function(lyn.word_t, [lyn.char_p])

    self.assertEqual(strlen(""), 0)
    self.assertEqual(strlen("h"), 1)
    self.assertEqual(strlen("he"), 2)
    self.assertEqual(strlen("hello"), 5)

    lightning.release()

Notice that we tell ``emit_function`` to create a function that returns a
``lyn.word_t``. This is a datatype whose size equals the computer's pointer
width, or ``sizeof(void*)``. ``lyn.word_t`` will then be either
``ctypes.c_int64`` or ``ctypes.c_int32``.

The parameter type ``lyn.char_p`` is a subclass of ``ctypes.c_char_p`` that
automatically converts strings to ``bytes`` objects. This is provided as a
compatibility convenience for Python 2 and 3 users. Use this type instead of
``ctypes.c_char_p``.

Example: Disassembling native code with Capstone
------------------------------------------------

If you install Capstone, you can use it as a disassembler for the generated
functions.  At some point, I'll integrate Capstone into Lyn::

    from lyn import Lightning, Register, word_t
    import capstone
    import ctypes

    lib = Lightning()
    jit = lib.state()

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
    incr = jit.emit_function(word_t, [word_t])

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

    jit.release()
    lib.release()

On my computer, this outputs::

    Compiled 34 bytes starting at 0x105ed3000
    0x105ed3000 48 83 ec 30    subq $0x30, %rsp
    0x105ed3004 48 89 2c 24    movq %rbp, (%rsp)
    0x105ed3008 48 89 e5       movq %rsp, %rbp
    0x105ed300b 48 83 ec 18    subq $0x18, %rsp
    0x105ed300f 48 89 f8       movq %rdi, %rax
    0x105ed3012 48 83 c0 1     addq $1, %rax
    0x105ed3016 48 89 ec       movq %rbp, %rsp
    0x105ed3019 48 8b 2c 24    movq (%rsp), %rbp
    0x105ed301d 48 83 c4 30    addq $0x30, %rsp
    0x105ed3021 c3             retq

    Raw bytes:
        \x48\x83\xec\x30\x48\x89\x2c\x24
        \x48\x89\xe5\x48\x83\xec\x18\x48
        \x89\xf8\x48\x83\xc0\x01\x48\x89
        \xec\x48\x8b\x2c\x24\x48\x83\xc4
        \x30\xc3

Capstone has a lot of neat features. I happen to favour AT&T assembly syntax,
but you can easily change that in the above code. But if you set ``md.detail =
True``, you'll be able to see implicit registers and a lot of other cool stuff.

Author and license
------------------

Copyright (C) 2015 Christian Stigen Larsen

Distributed under the LGPL v2.1 or later. You are allowed to change the license
on a particular copy to the LGPL v3.0, the GPL v2.0 or the GPL v3.0.
