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
import enum
import sys
import weakref

# Lyn modules
from .codes import Code


class NativeRegister(enum.IntEnum):
    # TODO: These values are currently specific for x86-64.
    RAX = 0
    R10 = 1
    R11 = 2
    R12 = 3
    RBX = 4
    R13 = 5
    R14 = 6
    R15 = 7


class Register(enum.IntEnum):
    R0 = NativeRegister.RAX
    R1 = NativeRegister.R10
    R2 = NativeRegister.R11
    R3 = NativeRegister.R12

    V0 = NativeRegister.RBX
    V1 = NativeRegister.R13
    V2 = NativeRegister.R14
    V3 = NativeRegister.R15


class State(object):
    """An active GNU Lightning JIT state."""

    def __init__(self, lib, state):
        self.lib = lib
        self.state = state
        self._functions = []
        self._destroyed = False

    def clear(self):
        self.lib._jit_clear_state(self.state)

    def __del__(self):
        self.destroy()

    def destroy(self):
        """Destroys the state, along with its functions.

        After calling this, you cannot call compiled functions anymore: Doing
        so will result in crashing the entire process.
        """
        if not self._destroyed:
            self._destroyed = True
            del self._functions
            self.lib._jit_destroy_state(self.state)

    def prolog(self):
        """Emits a function prologue."""
        self.lib._jit_prolog(self.state)

    def movi(self, dst, src):
        return self.lib._jit_new_node_ww(self.state, Code.movi, dst, src)

    def ret(self):
        self.lib._jit_ret(self.state)

    def retr(self, src):
        self.lib._jit_retr(self.state, src)

    def emit(self):
        return self.lib._jit_emit(self.state)

    def emit_function(self, return_type=ctypes.c_int, *argtypes):
        """Compiles code and returns a Python-callable function."""
        make_func = ctypes.CFUNCTYPE(return_type)
        code_ptr = self.emit()
        func = make_func(code_ptr)

        # Becase functions code are munmapped when we call _jit_destroy_state,
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
        self._finished = False

    def _load(self, liblightning=None):
        if liblightning is None:
            liblightning = ctypes.util.find_library("lightning")
        self.lib = ctypes.cdll.LoadLibrary(liblightning)

    def _init(self, program=None):
        if program is None:
            program = sys.executable
        self.lib.init_jit(program)

    def __del__(self):
        self._finish()

    def _finish(self):
        if not self._finished:
            self._finished = True
            self.lib.finish_jit()
            del self.lib

    def _set_signatures(self):
        """Sets return and parameter types for the foreign C functions."""

        # We currently pass structs as void pointers, and void returns are set
        # to None (TODO: Find out if None means void for ctypes)
        code_t = ctypes.c_int # It's an enum in lightning.h
        gpr_t = ctypes.c_int32
        node_p = ctypes.c_void_p
        pointer_t = ctypes.c_void_p
        state_p = ctypes.c_void_p
        void = None
        word_t = ctypes.c_int # NOTE: size should equal sizeof(void*)

        def sig(rettype, fname, *ptypes):
            func = getattr(self.lib, fname)
            func.restype = rettype
            func.argtypes = ptypes

        sig(node_p, "_jit_new_node_ww", state_p, code_t, word_t, word_t)
        sig(pointer_t, "_jit_emit", state_p)
        sig(state_p, "jit_new_state")
        sig(void, "_jit_clear_state", state_p)
        sig(void, "_jit_destroy_state", state_p)
        sig(void, "_jit_prolog", state_p)
        sig(void, "_jit_ret", state_p)
        sig(void, "_jit_retr", state_p, gpr_t)
        sig(void, "finish_jit")
        sig(void, "init_jit", ctypes.c_char_p)

    def new_state(self):
        """Returns a new JIT state. You have to clean up by calling .destroy()
        afterwards.
        """
        return State(weakref.proxy(self.lib), self.lib.jit_new_state())

    @contextlib.contextmanager
    def state(self):
        """Returns a new JIT state and cleans up afterwards."""
        state = self.new_state()
        yield state
        state.destroy()
