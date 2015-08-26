import ctypes
from lyn import Lightning, Register, word_t

with Lightning() as light:
    libc = light.load("c")

    with light.state() as jit:
        jit.prolog()
        arg = jit.arg()
        jit.getarg(Register.r0, arg)
        jit.pushargr(Register.r0)
        jit.finishi(ctypes.addressof(libc.atoi))
        jit.ret()
        jit.epilog()

        func = jit.emit_function(word_t)

        for n in range(100):
            out = func(n)
            print("func(%d) ==> %s (type %s)" % (n, out, type(out)))
