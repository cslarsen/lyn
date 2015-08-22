#!/usr/bin/env python

# This example creates a machine code function that returns the number 123.
# For this to work, the only thing you need is a shared-library install of GNU
# Lightning.

from lyn import *

lib = Lightning()

with lib.state() as jit:
    jit.prolog()
    jit.movi(Register.V0, 123)
    jit.retr(Register.V0)
    function = jit.emit_function()
    print("Should get 123 here: %s" % function())

# Note that with lib.state() ... destroys the state, so we actually have to
# call the function within that block. I'll fix that later, so it's more
# natural to use it (though, you have to keep the lyn.State object around for
# as long as you want to use the functions you've compiled.
