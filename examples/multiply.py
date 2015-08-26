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
