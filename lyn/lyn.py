# -*- encoding: utf-8 -*-

"""
lyn -- Bindings for GNU Lightning.

Copyright (C) 2015 Christian Stigen Larsen

Distributed under the LGPL v2.1 or later. You are allowed to change the license
on a particular copy to the LGPL v3.0, the GPL v2.0 or the GPL v3.0.
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
        if Lightning.wordsize == 64:
            get = self.lib._jit_getarg_l
        elif Lightning.wordsize == 32:
            get = self.lib._jit_getarg_i
        else:
            raise NotImplementedError("Unsupported wordsize %d" %
                    Lightning.wordsize)
        return Node(get(self.state, register, node.value))

    def getarg_l(self, register, node):
        assert(Lightning.wordsize == 64)
        return Node(self.lib._jit_getarg_l(self.state, register, node.value))

    def note(self, name=None, line=None):
        if line is None:
            line = inspect.currentframe().f_back.f_lineno

        if not name is None and not isinstance(name, bytes):
            name = six.b(name)

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
        if Lightning.wordsize == 64:
            code = Code.str_l
        elif Lightning.wordsize == 32:
            code = Code.str_i
        else:
            raise NotImplementedError("Unsupported wordsize %d" %
                    Lightning.wordsize)
        return self._ww(code, dst, src)

    def ldr(self, dst, src):
        if Lightning.wordsize == 64:
            code = Code.ldr_l
        elif Lightning.wordsize == 32:
            code = Code.ldr_i
        else:
            raise NotImplementedError("Unsupported wordsize %d" %
                    Lightning.wordsize)
        return self._ww(code, dst, src)

    def ret(self):
        self.lib._jit_ret(self.state)

    def retr(self, src):
        self.lib._jit_retr(self.state, src)

    def emit(self):
        return Pointer(self.lib._jit_emit(self.state))

    def emit_function(self, return_type=None, *argtypes):
        """Compiles code and returns a Python-callable function."""
        make_func = ctypes.CFUNCTYPE(return_type)
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


class Int64(ctypes.c_int64):
    @classmethod
    def from_param(cls, value):
        if not isinstance(value, ctypes.c_int64):
            value = ctypes.c_int64(value)
        return value


class Lightning(object):
    """The main GNU Lightning interface."""
    wordsize = 8*ctypes.sizeof(ctypes.c_void_p)

    # word_t property
    if wordsize == 64:
        word_t = ctypes.c_int64
    elif wordsize == 32:
        word_t = ctypes.c_int32
    else:
        raise NotSupportedError("Unsupported wordsize %d" %
                Lighting.wordsize)

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

        if not program is None and not isinstance(program, bytes):
            program = six.b(program)

        self.lib.init_jit(program)

    def release(self):
        self.lib.finish_jit()
        self.lib = None

    def _set_signatures(self):
        """Sets return and parameter types for the foreign C functions."""

        # We currently pass structs as void pointers, and void returns are set
        # to None (TODO: Find out if None means void for ctypes)
        code_t = ctypes.c_int
        gpr_t = ctypes.c_int32
        node_p = ctypes.c_void_p
        pointer_t = ctypes.c_void_p
        state_p = ctypes.c_void_p
        void = None
        word_t = Lightning.word_t

        def sig(rettype, fname, *ptypes):
            func = getattr(self.lib, fname)
            func.restype = rettype
            func.argtypes = ptypes

        sig(node_p, "_jit_arg", state_p)
        sig(node_p, "_jit_new_node_ww", state_p, code_t, word_t, word_t)
        sig(node_p, "_jit_new_node_www", state_p, code_t, word_t, word_t, word_t)
        sig(node_p, "_jit_note", state_p, ctypes.c_char_p, ctypes.c_int)
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
        sig(void, "init_jit", ctypes.c_char_p)

    def state(self):
        """Returns a new JIT state. You have to clean up by calling .destroy()
        afterwards.
        """
        return State(weakref.proxy(self.lib), self.lib.jit_new_state())

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.release()
