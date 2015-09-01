#!/usr/bin/env python

"""
Very incomplete assembler that takes the same input format as lightning.c does
(see check/ directory).
"""

import lyn
import sys

options = {
    "liblightning": None,
    "program": None,
    "verbose": True,
}

def log(s):
    if options["verbose"]:
        sys.stderr.write("%s\n" % s)
        sys.stderr.flush()

class Parser(object):
    def __init__(self, file):
        self.file = file

    def tokens(self):
        c = None
        while c != "":
            s = ""
            c = self.file.read(1)
            while c!="" and not c.isspace():
                s += c
                c = self.file.read(1)
            if s != "":
                yield s.strip()

    def parse(self):
        for token in self.tokens():
            sys.stdout.write(token + " ")
        print("")


class Compiler(object):
    def __init__(self, state, ast):
        self.jit = state
        self.ast = ast

    def compile(self):
        log("compiling")
        self.jit.prolog()
        self.jit.reti(0)
        return self.jit.emit_function(lyn.word_t)

def execute(program):
    log("executing")
    program()

def main():
    for fn in sys.argv[1:]:
        if fn.startswith("-"):
            continue

        log("opening %s" % fn)
        with open(fn, "rt") as f:
            with lyn.Lightning(options["liblightning"],
                               options["program"]) as lib:
                with lib.state() as jit:
                    p = Parser(f)
                    c = Compiler(jit, p.parse())
                    execute(c.compile())

if __name__ == "__main__":
    main()
