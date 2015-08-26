from lyn import *

with Lightning() as lib:
    with lib.state() as jit:
        jit.prolog()
        jit.getarg(R0, jit.arg())
        jit.getarg(R1, jit.arg())
        jit.mulr(R0, R0, R1)
        jit.retr(R0)
        jit.epilog()

        mul = jit.emit_function(word_t, [word_t, word_t])

        for a in xrange(-100, 100):
            for b in xrange(-100, 100):
                assert(mul(a,b) == a*b)
