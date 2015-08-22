lyn — Python bindings for GNU Lightning
=======================================

Lyn provides Python bindings for GNU Lightning, the light-weight just-in-time
(JIT) compiler that translated to native machine code.

"Lyn" is the Norwegian word for "lightning".

**NOTE:** This project is currently in extremely early stages!

Status
------

As mentioned above, Lyn is fledgling: I've just spent a few hours on it, so
almost nothing is supported and — in particular — I've only targeted x86-64
opcodes just yet.

In spite of this, I've managed to create a *really* simple program in Python
that is JIT-compiled to native x86-64 machine code: A glorious function that
returns the value of 123! Here's the code::

    #!/usr/bin/env python

    from lyn import *

    lib = Lightning()

    with lib.state() as jit:
        jit.prolog()

        # The actual code
        jit.movi(Register.V0, 123)
        jit.retr(Register.V0)

        function = jit.emit_function()
        print("Should get 123 here: %s" % function())

I'm using ctypes for creating the bindings, which comes with some challenges:
GNU Lightning is written in C, and relies heavily on compile-time macros that
define machine specific opcodes, register values and so on. Because of this, it
would be more natural to simply create bindings through a C extension. On the
other hand, though, ctypes makes it possible to ship Lyn as a platform
independent, pure Python source. I'll chew on this for a while, and we'll see
what happens.

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
