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
