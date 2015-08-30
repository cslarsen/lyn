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

import ctypes
import ctypes.util
import inspect
import six
import sys
import weakref

from .emit import Emitter

#: The bit size of GNU Lightning words, equal to sizeof(void*).
wordsize = 8*ctypes.sizeof(ctypes.c_void_p)

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
        self._executable = None

    def _load(self, liblightning=None):
        if liblightning is None:
            liblightning = ctypes.util.find_library("lightning")
        self.lib = ctypes.cdll.LoadLibrary(liblightning)

    def load(self, name):
        """Loads and returns foreign library."""
        name = ctypes.util.find_library(name)
        return ctypes.cdll.LoadLibrary(name)

    def _init(self, program=None):
        if program is None:
            program = sys.executable

        # We need to keep a working pointer to the init_jit argument.
        self._executable = ctypes.c_char_p(six.b(program))
        self.lib.init_jit(self._executable)

    def release(self):
        self.lib.finish_jit()
        self.lib = None

    def _set_signatures(self):
        """Sets return and parameter types for the foreign C functions."""

        # We currently pass structs as void pointers.
        code_t = ctypes.c_int
        gpr_t = ctypes.c_int32
        int32_t = ctypes.c_int32
        node_p = ctypes.c_void_p
        pointer_t = ctypes.c_void_p
        state_p = ctypes.c_void_p
        void = None

        def sig(rettype, fname, *ptypes):
            func = getattr(self.lib, fname)
            func.restype = rettype
            func.argtypes = ptypes

        sig(node_p, "_jit_arg", state_p)
        sig(node_p, "_jit_finishi", state_p, pointer_t)
        sig(node_p, "_jit_forward", state_p)
        sig(node_p, "_jit_indirect", state_p)
        sig(node_p, "_jit_label", state_p)
        sig(node_p, "_jit_new_node_p", state_p, code_t, pointer_t)
        sig(node_p, "_jit_new_node_pww", state_p, code_t, pointer_t, word_t, word_t)
        sig(node_p, "_jit_new_node_qww", state_p, code_t, int32_t, int32_t, word_t)
        sig(node_p, "_jit_new_node_w", state_p, code_t, word_t)
        sig(node_p, "_jit_new_node_ww", state_p, code_t, word_t, word_t)
        sig(node_p, "_jit_new_node_www", state_p, code_t, word_t, word_t, word_t)
        sig(node_p, "_jit_note", state_p, char_p, ctypes.c_int)
        sig(pointer_t, "_jit_address", state_p, node_p)
        sig(pointer_t, "_jit_emit", state_p)
        sig(state_p, "jit_new_state")
        sig(void, "_jit_clear_state", state_p)
        sig(void, "_jit_destroy_state", state_p)
        sig(void, "_jit_ellipsis", state_p)
        sig(void, "_jit_epilog", state_p)
        sig(void, "_jit_finishr", state_p, gpr_t)
        sig(void, "_jit_getarg_i", state_p, gpr_t, node_p)
        sig(void, "_jit_getarg_l", state_p, gpr_t, node_p)
        sig(void, "_jit_link", state_p, node_p)
        sig(void, "_jit_patch", state_p, node_p)
        sig(void, "_jit_patch_at", state_p, node_p, node_p)
        sig(void, "_jit_prepare", state_p)
        sig(void, "_jit_prolog", state_p)
        sig(void, "_jit_pushargi", state_p, word_t)
        sig(void, "_jit_pushargr", state_p, gpr_t)
        sig(void, "_jit_ret", state_p)
        sig(void, "_jit_reti", state_p, word_t)
        sig(void, "_jit_retr", state_p, gpr_t)
        sig(void, "_jit_retval_c", state_p, gpr_t)
        sig(void, "_jit_retval_i", state_p, gpr_t)
        sig(void, "_jit_retval_s", state_p, gpr_t)
        sig(void, "_jit_retval_uc", state_p, gpr_t)
        sig(void, "_jit_retval_us", state_p, gpr_t)
        sig(void, "finish_jit")
        sig(void, "init_jit", ctypes.c_char_p) # NOTE: Don't use char_p

        if wordsize == 64:
            sig(void, "_jit_retval_l", state_p, gpr_t)
            sig(void, "_jit_retval_ui", state_p, gpr_t)

    def state(self):
        """Returns a new JIT state. You have to clean up by calling .destroy()
        afterwards.
        """
        return Emitter(weakref.proxy(self.lib), self.lib.jit_new_state())

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.release()
