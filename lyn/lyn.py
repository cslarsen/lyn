# -*- encoding: utf-8 -*-

"""
lyn -- Python bindings for GNU Lightning.

GNU lightning is a library that generates assembly language code at run-time;
it is very fast, making it ideal for Just-In-Time compilers, and it abstracts
over the target CPU, as it exposes to the clients a standardized RISC
instruction set inspired by the MIPS and SPARC chips.

The above paragraph was taken from its site at
http://www.gnu.org/software/lightning/

GNU Lightning

    Copyright (C) 2012, 2013  Free Software Foundation, Inc.
    Distributed under the GPL v3.
    Written by Paulo Cesar Pereira de Andrade

Lyn

    Copyright (C) 2015 Christian Stigen Larsen

    Distributed under the LGPL 2.1 or later. You are allowed to change the
    license on a particular copy to the LGPL 3.0, the GPL 2.0 or the GPL 3.0.
"""

import contextlib
import ctypes
import ctypes.util
import inspect
import six
import sys
import weakref

from .codes import Code
from .registers import Register

#: The bit size of GNU Lightning words, equal to sizeof(void*).
wordsize = ctypes.sizeof(ctypes.c_void_p) * 8

#: The word type, used for parameter and return types in functions.
word_t = {64: ctypes.c_int64,
          32: ctypes.c_int32,
          16: ctypes.c_int16,
           8: ctypes.c_int8}.get(wordsize, ctypes.c_int)

word_t.__name__ = "word_t"
word_t.__doc__ = "Parameter type whose size equals sizeof(void*)."

class char_p(ctypes.c_char_p):
    """Drop-in replacement for ctypes.c_char_p that automatically converts
    string arguments to bytes.

    This is useful for Python 3, where you would have to explictly pass byte
    strings when calling foreign functions, but also works for Python 2.
    """
    @classmethod
    def from_param(cls, value):
        if value is not None and not isinstance(value, bytes):
            value = six.b(value)
        return value


class Node(object):
    """A node in the code (jit_node_t pointer)."""
    def __init__(self, jit_node_ptr):
        self.value = jit_node_ptr

    def __repr__(self):
        return "<Node: jit_node_t at 0x%x>" % self.value


class Pointer(object):
    """An internal pointer used by GNU Lightning (jit_pointer_t)."""
    def __init__(self, jit_pointer_t):
        self.value = jit_pointer_t

    def __sub__(self, other):
        return Pointer(self.value - other.value)

    def __add__(self, other):
        return Pointer(self.value - other.value)

    def __int__(self):
        return self.value

    def __repr__(self):
        return "<Pointer: jit_pointer_t to 0x%x>" % self.value


class State(object):
    """An active GNU Lightning JIT state."""

    def __init__(self, lib, state):
        self._functions = []
        self.lib = lib
        self.state = state

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.release()

    def clear(self):
        self.lib._jit_clear_state(self.state)

    def release(self):
        """Destroys the state, along with its functions.

        After calling this, you cannot call compiled functions anymore: Doing
        so will result in crashing the entire process.
        """
        del self._functions
        self.lib._jit_destroy_state(self.state)
        self.lib = None

    def _www(self, code, *args):
        return Node(self.lib._jit_new_node_www(self.state, code, *args))

    def _ww(self, code, *args):
        return Node(self.lib._jit_new_node_ww(self.state, code, *args))

    def prolog(self):
        """Emits a function prologue."""
        self.lib._jit_prolog(self.state)

    def epilog(self):
        """Emits a function epilogue.

        Calling this function is optional.
        """
        self.lib._jit_epilog(self.state)

    def address(self, node):
        return Pointer(self.lib._jit_address(self.state, node.value))

    def arg(self):
        return Node(self.lib._jit_arg(self.state))

    def getarg(self, register, node):
        if wordsize == 32:
            return self.getarg_i(register, node)
        else:
            return self.getarg_l(register, node)

    def getarg_l(self, register, node):
        return Node(self.lib._jit_getarg_l(self.state, register, node.value))

    def getarg_i(self, register, node):
        return Node(self.lib._jit_getarg_i(self.state, register, node.value))

    def note(self, name=None, line=None):
        # Get caller's line number
        if line is None:
            line = inspect.currentframe().f_back.f_lineno

        return Node(self.lib._jit_note(self.state, name, line))

    def movi(self, register, immediate):
        return self._ww(Code.movi, register, immediate)

    def addi(self, dst, src, immediate):
        return self._www(Code.addi, dst, src, immediate)

    def addr(self, dst, src1, src2):
        return self._www(Code.addr, dst, src1, src2)

    def mulr(self, dst, src1, src2):
        return self._www(Code.mulr, dst, src1, src2)

    def muli(self, dst, src, immediate):
        return self._www(Code.muli, dst, src, immediate)

    def str(self, dst, src):
        if wordsize == 32:
            return self.str_i(dst, src)
        else:
            return self.str_l(dst, src)

    def str_i(self, dst, src):
        return self._ww(Code.str_i, dst, src)

    def str_l(self, dst, src):
        return self._ww(Code.str_l, dst, src)

    def ldr(self, dst, src):
        if wordsize == 32:
            return self.ldr_i(dst, src)
        else:
            return self.ldr_l(dst, src)

    def ldr_l(self, dst, src):
        return self._ww(Code.ldr_l, dst, src)

    def ldr_i(self, dst, src):
        return self._ww(Code.ldr_i, dst, src)

    def ret(self):
        self.lib._jit_ret(self.state)

    def retr(self, src):
        self.lib._jit_retr(self.state, src)

    def emit(self):
        return Pointer(self.lib._jit_emit(self.state))

    def emit_function(self, return_type=None, argtypes=[]):
        """Compiles code and returns a Python-callable function."""
        make_func = ctypes.CFUNCTYPE(return_type, *argtypes)
        code = self.emit()
        func = make_func(code.value)

        # Save this in case anyone wants to disassemble using external
        # libraries
        func.address = code

        # Because functions code are munmapped when we call _jit_destroy_state,
        # we need to return weakrefs to the functions. Otherwise, a user could
        # call a function that points to invalid memory.
        self._functions.append(func)
        return weakref.proxy(func)


class Lightning(object):
    """The main GNU Lightning interface."""

    def __init__(self, liblightning=None, program=None):
        """Bindings to GNU Lightning library.

        Args:
            liblightning: Set to override path to liblightning.
            program: Set to override argument to init_jit, used with bfd.
        """
        self._load(liblightning)
        self._set_signatures()
        self._init()

    def _load(self, liblightning=None):
        if liblightning is None:
            liblightning = ctypes.util.find_library("lightning")
        self.lib = ctypes.cdll.LoadLibrary(liblightning)

    def _init(self, program=None):
        if program is None:
            program = sys.executable

        self.lib.init_jit(program)

    def release(self):
        self.lib.finish_jit()
        self.lib = None

    def _set_signatures(self):
        """Sets return and parameter types for the foreign C functions."""

        # We currently pass structs as void pointers.
        code_t = ctypes.c_int
        gpr_t = ctypes.c_int32
        node_p = ctypes.c_void_p
        pointer_t = ctypes.c_void_p
        state_p = ctypes.c_void_p
        void = None

        def sig(rettype, fname, *ptypes):
            func = getattr(self.lib, fname)
            func.restype = rettype
            func.argtypes = ptypes

        sig(node_p, "_jit_arg", state_p)
        sig(node_p, "_jit_new_node_ww", state_p, code_t, word_t, word_t)
        sig(node_p, "_jit_new_node_www", state_p, code_t, word_t, word_t, word_t)
        sig(node_p, "_jit_note", state_p, char_p, ctypes.c_int)
        sig(pointer_t, "_jit_address", state_p, node_p)
        sig(pointer_t, "_jit_emit", state_p)
        sig(state_p, "jit_new_state")
        sig(void, "_jit_clear_state", state_p)
        sig(void, "_jit_destroy_state", state_p)
        sig(void, "_jit_epilog", state_p)
        sig(void, "_jit_getarg_i", state_p, gpr_t, node_p)
        sig(void, "_jit_getarg_l", state_p, gpr_t, node_p)
        sig(void, "_jit_prolog", state_p)
        sig(void, "_jit_ret", state_p)
        sig(void, "_jit_retr", state_p, gpr_t)
        sig(void, "finish_jit")
        sig(void, "init_jit", char_p)

    def state(self):
        """Returns a new JIT state. You have to clean up by calling .destroy()
        afterwards.
        """
        return State(weakref.proxy(self.lib), self.lib.jit_new_state())

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.release()
