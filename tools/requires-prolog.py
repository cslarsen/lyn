"""
Lists all Emitter instructions that segfaults the process it there is no
``jit.prolog()`` call.
"""

from lyn import *
from lyn.emit import *
import inspect
import os
import sys

def test(funcname):
    pid = os.fork()

    if pid == 0:
        with Lightning() as lib:
            with lib.state() as jit:
                func = getattr(jit, funcname)

                if func is None:
                    sys.exit(0)

                spec = inspect.getargspec(func)
                parms = len(spec.args)
                args = [0]*(parms-1)

                try:
                    func(*args)
                except Exception as e:
                    pass

                sys.exit(0)
    else:
        _, status = os.waitpid(pid, 0)
        if os.WTERMSIG(status) == 11:
            print("%s ... segfault" % funcname)
            return False
        return status == 0

def main():
    funcs = dir(Emitter)
    for fname in funcs:
        if not fname.startswith("__"):
            test(fname)

if __name__ == "__main__":
    main()
