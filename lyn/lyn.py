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

from .codes import Code

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

    def _pww(self, code, *args):
        return Node(self.lib._jit_new_node_pww(self.state, code, *args))

    def _p(self, code, *args):
        return Node(self.lib._jit_new_node_p(self.state, code, *args))

    def _qww(self, code, *args):
        return Node(self.lib._jit_new_node_qww(self.state, code, *args))

    def _ww(self, code, *args):
        return Node(self.lib._jit_new_node_ww(self.state, code, *args))

    def _w(self, code, *args):
        return Node(self.lib._jit_new_node_w(self.state, code, *args))

    def _w(self, code, *args):
        return Node(self.lib._jit_new_node_w(self.state, code, *args))

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

    def beqr(self, v, w):
        return self._pww(Code.beqr, None, v, w)

    def beqi(self, node, register, immediate):
        return self._pww(Code.beqi, node.value, register, immediate)

    def jmpr(self, register):
        return self._w(Code.jmpr, register)

    def jmpi(self):
        return Pointer(self._p(Code.jmpr, None))

    def label(self):
        return Node(self.lib._jit_label(self.state))

    def forward(self):
        return Node(self.lib._jit_forward(self.state))

    def indirect(self):
        return Node(self.lib._jit_indirect(self.state))

    def link(self, node):
        self.lib._jit_link(self.state, node.value)

    def patch(self, node):
        self.lib._jit_patch(self.state, node.value)

    def patch_at(self, node1, node2):
        self.lib._jit_patch_at(self.state, node1.value, node2.value)

    def arg(self):
        # TODO: _c _uc _s _us _i _ui _l
        return Node(self.lib._jit_arg(self.state))

    def getarg(self, register, node):
        # TODO: _c _uc _s _us _i _ui _l
        if wordsize == 32:
            return self.getarg_i(register, node)
        else:
            return self.getarg_l(register, node)

    def getarg_l(self, register, node):
        return Node(self.lib._jit_getarg_l(self.state, register, node.value))

    def getarg_i(self, register, node):
        return Node(self.lib._jit_getarg_i(self.state, register, node.value))

    def putargr(self, register, node):
        return self.lib._jit_putargr(self.state, register, node.value)

    def putargi(self, register, node):
        return self.lib._jit_putargi(self.state, register, node.value)

    def negr(self, dst, src):
        return self._ww(Code.negr, dst, src)

    def negr_f(self, dst, src):
        return self._ww(Code.negr_f, dst, src)

    def negr_d(self, dst, src):
        return self._ww(Code.negr_d, dst, src)

    def comr(self, dst, src):
        return self._ww(Code.comr, dst, src)

    def comr_f(self, dst, src):
        return self._ww(Code.comr_f, dst, src)

    def comr_d(self, dst, src):
        return self._ww(Code.comr_d, dst, src)

    def absr_f(self, register):
        return self._ww(Code.absr_f, register)

    def absr_d(self, register):
        return self._ww(Code.absr_d, register)

    def sqrtr_f(self, register):
        return self._ww(Code.sqrtr_f, register)

    def sqrtr_d(self, register):
        return self._ww(Code.sqrtr_d, register)

    def note(self, name=None, line=None):
        # Get caller's line number
        if line is None:
            line = inspect.currentframe().f_back.f_lineno

        return Node(self.lib._jit_note(self.state, name, line))

    def movi(self, register, immediate):
        return self._ww(Code.movi, register, immediate)

    def addi(self, dst, src, immediate):
        return self._www(Code.addi, dst, src, immediate)

    def addi_f(self, dst, src, immediate):
        return self._www(Code.addi_f, dst, src, immediate)

    def addi_d(self, dst, src, immediate):
        return self._www(Code.addi_d, dst, src, immediate)

    def addr(self, dst, src1, src2):
        return self._www(Code.addr, dst, src1, src2)

    def prepare(self):
        return self.lib._jit_prepare(self.state)

    def pushargr(self, register):
        return self.lib._jit_pushargr(self.state, register)

    def pushargi(self, immediate):
        return self.lib._jit_pushargi(self.state, immediate)

    def addr_f(self, dst, src1, src2):
        return self._www(Code.addr_f, dst, src1, src2)

    def addr_d(self, dst, src1, src2):
        return self._www(Code.addr_d, dst, src1, src2)

    def addxr(self, dst, src1, src2):
        return self._www(Code.addxr, dst, src1, src2)

    def addxi(self, dst, src1, src2):
        return self._www(Code.addxir, dst, src1, src2)

    def addcr(self, dst, src1, src2):
        return self._www(Code.addcr, dst, src1, src2)

    def addci(self, dst, src1, src2):
        return self._www(Code.addci, dst, src1, src2)

    def subi(self, dst, src, immediate):
        return self._www(Code.subi, dst, src, immediate)

    def subi_f(self, dst, src, immediate):
        return self._www(Code.subi_f, dst, src, immediate)

    def subi_d(self, dst, src, immediate):
        return self._www(Code.subi_d, dst, src, immediate)

    def subr(self, dst, src1, src2):
        return self._www(Code.subr, dst, src1, src2)

    def subr_f(self, dst, src1, src2):
        return self._www(Code.subr_f, dst, src1, src2)

    def subr_d(self, dst, src1, src2):
        return self._www(Code.subr_d, dst, src1, src2)

    def subxr(self, dst, src1, src2):
        return self._www(Code.subxr, dst, src1, src2)

    def subxi(self, dst, src1, src2):
        return self._www(Code.subxi, dst, src1, src2)

    def subcr(self, dst, src1, src2):
        return self._www(Code.subcr, dst, src1, src2)

    def subci(self, dst, src1, src2):
        return self._www(Code.subci, dst, src1, src2)

    def rsbr(self, dst, src1, src2):
        return self._www(Code.rsbr, dst, src1, src2)

    def rsbr_f(self, dst, src1, src2):
        return self.subr_f(dst, src1, src2)

    def rsbr_d(self, dst, src1, src2):
        return self._www(Code.rsbr_d, dst, src1, src2)

    def rsbi(self, dst, src1, src2):
        return self._www(Code.rsbi, dst, src1, src2)

    def rsbi_f(self, dst, src1, src2):
        return self._wwf(Code.rsbi_f, dst, src1, src2)

    def rsbi_i(self, dst, src1, src2):
        return self._www(Code.rsbi_i, dst, src1, src2)

    def mulr(self, dst, src1, src2):
        return self._www(Code.mulr, dst, src1, src2)

    def muli(self, dst, src, immediate):
        return self._www(Code.muli, dst, src, immediate)

    def divr(self, dst, src1, src2):
        return self._www(Code.divr, dst, src1, src2)

    def divr_u(self, dst, src1, src2):
        return self._www(Code.divr_u, dst, src1, src2)

    def divr_f(self, dst, src1, src2):
        return self._www(Code.divr_f, dst, src1, src2)

    def divr_d(self, dst, src1, src2):
        return self._www(Code.divr_d, dst, src1, src2)

    def divi(self, dst, src, immediate):
        return self._www(Code.divi, dst, src, immediate)

    def divi_u(self, dst, src, immediate):
        return self._www(Code.divi_u, dst, src, immediate)

    def divi_f(self, dst, src, immediate):
        return self._www(Code.divi_f, dst, src, immediate)

    def divi_d(self, dst, src, immediate):
        return self._www(Code.divi_d, dst, src, immediate)

    def remr(self, dst, src1, src2):
        return self._www(Code.remr, dst, src1, src2)

    def remr_u(self, dst, src1, src2):
        return self._www(Code.remr_u, dst, src1, src2)

    def remi(self, dst, src, immediate):
        return self._www(Code.remi, dst, src, immediate)

    def remi_u(self, dst, src, immediate):
        return self._www(Code.remi_u, dst, src, immediate)

    def andr(self, dst, src1, src2):
        return self._www(Code.andr, dst, src1, src2)

    def andi(self, dst, src, immediate):
        return self._www(Code.andi, dst, src, immediate)

    def orr(self, dst, src1, src2):
        return self._www(Code.orr, dst, src1, src2)

    def ori(self, dst, src, immediate):
        return self._www(Code.ori, dst, src, immediate)

    def xorr(self, dst, src1, src2):
        return self._www(Code.xorr, dst, src1, src2)

    def xori(self, dst, src, immediate):
        return self._www(Code.xori, dst, src, immediate)

    def lshr(self, dst, src1, src2):
        return self._www(Code.lshr, dst, src1, src2)

    def lshi(self, dst, src, immediate):
        return self._www(Code.lshi, dst, src, immediate)

    def rshr(self, dst, src1, src2):
        """Right shift.

        The sign bit is propagated unless using the _u modifier.
        """
        return self._www(Code.rshr, dst, src1, src2)

    def rshr_u(self, dst, src1, src2):
        """Right shift.

        The sign bit is propagated unless using the _u modifier.
        """
        return self._www(Code.rshr_u, dst, src1, src2)

    def rshi(self, dst, src, immediate):
        return self._www(Code.rshi, dst, src, immediate)

    def rshi_u(self, dst, src, immediate):
        """Right shift.

        The sign bit is propagated unless using the _u modifier.
        """
        return self._www(Code.rshi_u, dst, src, immediate)

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

    def reti(self, immediate):
        self.lib._jit_reti(self.state, immediate)

    def retval_i(self, register):
        return self.lib._jit_retval_i(self.state, register)

    def retval_l(self, register):
        return self.lib._jit_retval_l(self.state, register)

    def retval(self, register):
        if wordsize == 32:
            return self.retval_i(register)
        else:
            return self.retval_l(register)


    def emit(self):
        return Pointer(self.lib._jit_emit(self.state))

    def callr(self, register):
        return self._w(Code.callr, register)

    def calli(self, register):
        return self._p(Code.calli, register)

    def finishr(self, register):
        self._jit_finishr(self.state, register)

    def finishi(self, pointer):
        return Node(self.lib._jit_finishi(self.state, pointer))

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

    def qmulr(self, o1, o2, o3, o4):
        return self._qww(Code.qmulr, o1, o2, o3, o4)

    def qmulr_u(self, o1, o2, o3, o4):
        return self._qww(Code.qmulr_u, o1, o2, o3, o4)

    def qmuli(self, o1, o2, o3, o4):
        return self._qww(Code.qmuli, o1, o2, o3, o4)

    def qmuli_u(self, o1, o2, o3, o4):
        return self._qww(Code.qmuli_u, o1, o2, o3, o4)

    def qdivr(self, o1, o2, o3, o4):
        return self._qww(Code.qdivr, o1, o2, o3, o4)

    def qdivr_u(self, o1, o2, o3, o4):
        return self._qww(Code.qdivr_u, o1, o2, o3, o4)

    def qdivi(self, o1, o2, o3, o4):
        return self._qww(Code.qdivi, o1, o2, o3, o4)

    def qdivi_u(self, o1, o2, o3, o4):
        return self._qww(Code.qdivi_u, o1, o2, o3, o4)



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

    def load(self, name):
        """Loads and returns foreign library."""
        name = ctypes.util.find_library(name)
        return ctypes.cdll.LoadLibrary(name)

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
        sig(void, "init_jit", char_p)

        if wordsize == 64:
            sig(void, "_jit_retval_l", state_p, gpr_t)
            sig(void, "_jit_retval_ui", state_p, gpr_t)

    def state(self):
        """Returns a new JIT state. You have to clean up by calling .destroy()
        afterwards.
        """
        return State(weakref.proxy(self.lib), self.lib.jit_new_state())

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.release()
