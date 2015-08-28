import ctypes
import inspect
import weakref

from .codes import Code
from .node import Node
from .pointer import Pointer

_Emitter__wordsize = 8*ctypes.sizeof(ctypes.c_void_p)

class State(object):
    """An active GNU Lightning state."""
    def __init__(self, lib, state):
        self.functions = []
        self.lib = lib
        self.state = state
        self._prolog = False

    def _assert_prolog(self):
        """Used to guard against missing prologs.

        E.g., calling ``pushargi`` without a prior call to ``prolog()`` will
        result in a segfault.
        """
        if self._prolog == False:
            raise RuntimeError("Requires a prolog")

    def release(self):
        """Destroys the state, along with its functions."""
        del self.functions
        self.lib._jit_destroy_state(self.state)
        self.lib = None

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.release()

    def clear(self):
        """Clears state so it can be used for generating entirely new
        instructions."""
        self.lib._jit_clear_state(self.state)

    def emit_function(self, return_type=None, argtypes=[], proxy=True):
        """Compiles code and returns a Python-callable function."""

        if argtypes is not None:
            make_func = ctypes.CFUNCTYPE(return_type, *argtypes)
        else:
            make_func = ctypes.CFUNCTYPE(return_type)

        code = self.emit()
        func = make_func(code.value)

        # Save this in case anyone wants to disassemble using external
        # libraries
        func.address = code

        # Because functions code are munmapped when we call _jit_destroy_state,
        # we need to return weakrefs to the functions. Otherwise, a user could
        # call a function that points to invalid memory.
        if proxy:
            self.functions.append(func)
            return weakref.proxy(func)
        else:
            return func

    def emit_function_fast(self, return_type=None):
        """As emit_function, but returns a function with less calling overhead.

        Equivalent to calling:

            emit_function(..., argtypes=None, proxy=False)

        In cases where you absolutely must call the generated code many, many
        times, this emitter is a tad faster: In informal tests, it has 2.2
        times less overhead than ``emit_function``, but still has an overhead
        of 1.7 times compared to calling a pure Python function.

        The following caveats apply:

            - The returned function is not a weakref, meaning that if you
              destroy the JIT state, the function will point to a dangling
              memory region. Calling it will then result in an immediate
              segfault, or worse. You can use the ``release`` methods of the
              Lyn Lightning and Lyn State objects to control the lifetime
              yourself.

            - Argument types are not set, meaning that the number of arguments
              and their types are not checked at call time. If you need to pass
              special objects, like strings or structs, you have to create them
              yourself using ctypes and pass their addresses.

        Normally, you'll want to use ``emit_function``, which is safer. But in
        cases where you'll be calling the generated functions *many* times,
        this one is a tad faster: The overhead is reduced by about 2.2 times
        (in informal tests) compared to emit_function, but there is still
        overhead of about 1.7 times compared to what a native Python call would
        have. So, the general strategy is to build large functions with Lyn,
        reducing the number of function calls you make from Python, or use this
        function, which is a bit more cumbersome to deal with.
        """
        return self.emit_function(return_type, argtypes=None, proxy=None)


class Emitter(State):
    """Emits GNU Lightning instructions into its current state.

    For a detailed explanation of each instruction, please refer to
    http://www.gnu.org/software/lightning/manual/lightning.html#The-instruction-set
    """

    def __init__(self, *args, **kw):
        super(Emitter, self).__init__(*args, **kw)

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

    def address(self, node):
        return Pointer(self.lib._jit_address(self.state, node.value))

    def getarg(self, register, node):
        # TODO: _c _uc _s _us _i _ui _l
        if __wordsize == 32:
            return self.getarg_i(register, node)
        else:
            return self.getarg_l(register, node)

    def getarg_l(self, register, node):
        self._assert_prolog()
        return Node(self.lib._jit_getarg_l(self.state, register, node.value))

    def putargr(self, register, node):
        return self.lib._jit_putargr(self.state, register, node.value)

    def putargi(self, register, node):
        return self.lib._jit_putargi(self.state, register, node.value)

    def note(self, name=None, line=None):
        # Get caller's line number
        if line is None:
            line = inspect.currentframe().f_back.f_lineno

        return Node(self.lib._jit_note(self.state, name, line))

    def str(self, dst, src):
        if __wordsize == 32:
            return self.str_i(dst, src)
        else:
            return self.str_l(dst, src)

    def str_l(self, dst, src):
        return self._ww(Code.str_l, dst, src)

    def ldr(self, dst, src):
        if __wordsize == 32:
            return self.ldr_i(dst, src)
        else:
            return self.ldr_l(dst, src)

    def ldr_l(self, dst, src):
        return self._ww(Code.ldr_l, dst, src)

    def emit(self):
        return Pointer(self.lib._jit_emit(self.state))

    def live(self, u):
        return self.lib._w(Code.live, u)

    def align(self, u):
        return self.lib._w(Code.align, u)

    def name(self, u):
        return Node(self.lib._jit_name(self.state, u))

    def label(self):
        return Node(self.lib._jit_label(self.state))

    def forward(self):
        return Node(self.lib._jit_forward(self.state))

    def indirect(self):
        return Node(self.lib._jit_indirect(self.state))

    def link(self, node):
        return self.lib._jit_link(self.state, node.value)

    def prolog(self):
        if self._prolog == True:
            raise ValueError("Prolog already emitted")
        self._prolog = True
        return self.lib._jit_prolog(self.state)

    def ellipsis(self):
        return self.lib._jit_ellipsis(self.state)

    def allocai(self, u):
        return self.lib._jit_allocai(self.state, u)

    def arg(self):
        self._assert_prolog()
        return Node(self.lib._jit_arg(self.state))

    def getarg_c(self, u, v):
        return self.lib._jit_getarg_c(self.state, u, v)

    def getarg_uc(self, u, v):
        return self.lib._jit_getarg_uc(self.state, u, v)

    def getarg_s(self, u, v):
        return self.lib._jit_getarg_s(self.state, u, v)

    def getarg_us(self, u, v):
        return self.lib._jit_getarg_us(self.state, u, v)

    def getarg_i(self, u, v):
        return self.lib._jit_getarg_i(self.state, u, v)

    def addr(self, u, v, w):
        return self._www(Code.addr, u, v, w)

    def addi(self, u, v, w):
        return self._www(Code.addi, u, v, w)

    def addcr(self, u, v, w):
        return self._www(Code.addcr, u, v, w)

    def addci(self, u, v, w):
        return self._www(Code.addci, u, v, w)

    def addxr(self, u, v, w):
        return self._www(Code.addxr, u, v, w)

    def addxi(self, u, v, w):
        return self._www(Code.addxi, u, v, w)

    def subr(self, u, v, w):
        return self._www(Code.subr, u, v, w)

    def subi(self, u, v, w):
        return self._www(Code.subi, u, v, w)

    def subcr(self, u, v, w):
        return self._www(Code.subcr, u, v, w)

    def subci(self, u, v, w):
        return self._www(Code.subci, u, v, w)

    def subxr(self, u, v, w):
        return self._www(Code.subxr, u, v, w)

    def subxi(self, u, v, w):
        return self._www(Code.subxi, u, v, w)

    def rsbr(self, u, v, w):
        return self.jit_subr(u, w, v)

    def rsbi(self, u, v, w):
        return self._www(Code.rsbi, u, v, w)

    def mulr(self, u, v, w):
        return self._www(Code.mulr, u, v, w)

    def muli(self, u, v, w):
        return self._www(Code.muli, u, v, w)

    def qmulr(self, l, h, v, w):
        return self._qww(Code.qmulr, l, h, v, w)

    def qmuli(self, l, h, v, w):
        return self._qww(Code.qmuli, l, h, v, w)

    def qmulr_u(self, l, h, v, w):
        return self._qww(Code.qmulr_u, l, h, v, w)

    def qmuli_u(self, l, h, v, w):
        return self._qww(Code.qmuli_u, l, h, v, w)

    def divr(self, u, v, w):
        return self._www(Code.divr, u, v, w)

    def divi(self, u, v, w):
        return self._www(Code.divi, u, v, w)

    def divr_u(self, u, v, w):
        return self._www(Code.divr_u, u, v, w)

    def divi_u(self, u, v, w):
        return self._www(Code.divi_u, u, v, w)

    def qdivr(self, l, h, v, w):
        return self._qww(Code.qdivr, l, h, v, w)

    def qdivi(self, l, h, v, w):
        return self._qww(Code.qdivi, l, h, v, w)

    def qdivr_u(self, l, h, v, w):
        return self._qww(Code.qdivr_u, l, h, v, w)

    def qdivi_u(self, l, h, v, w):
        return self._qww(Code.qdivi_u, l, h, v, w)

    def remr(self, u, v, w):
        return self._www(Code.remr, u, v, w)

    def remi(self, u, v, w):
        return self._www(Code.remi, u, v, w)

    def remr_u(self, u, v, w):
        return self._www(Code.remr_u, u, v, w)

    def remi_u(self, u, v, w):
        return self._www(Code.remi_u, u, v, w)

    def andr(self, u, v, w):
        return self._www(Code.andr, u, v, w)

    def andi(self, u, v, w):
        return self._www(Code.andi, u, v, w)

    def orr(self, u, v, w):
        return self._www(Code.orr, u, v, w)

    def ori(self, u, v, w):
        return self._www(Code.ori, u, v, w)

    def xorr(self, u, v, w):
        return self._www(Code.xorr, u, v, w)

    def xori(self, u, v, w):
        return self._www(Code.xori, u, v, w)

    def lshr(self, u, v, w):
        return self._www(Code.lshr, u, v, w)

    def lshi(self, u, v, w):
        return self._www(Code.lshi, u, v, w)

    def rshr(self, u, v, w):
        return self._www(Code.rshr, u, v, w)

    def rshi(self, u, v, w):
        return self._www(Code.rshi, u, v, w)

    def rshr_u(self, u, v, w):
        return self._www(Code.rshr_u, u, v, w)

    def rshi_u(self, u, v, w):
        return self._www(Code.rshi_u, u, v, w)

    def negr(self, u, v):
        return self._ww(Code.negr, u, v)

    def comr(self, u, v):
        return self._ww(Code.comr, u, v)

    def ltr(self, u, v, w):
        return self._www(Code.ltr, u, v, w)

    def lti(self, u, v, w):
        return self._www(Code.lti, u, v, w)

    def ltr_u(self, u, v, w):
        return self._www(Code.ltr_u, u, v, w)

    def lti_u(self, u, v, w):
        return self._www(Code.lti_u, u, v, w)

    def ler(self, u, v, w):
        return self._www(Code.ler, u, v, w)

    def lei(self, u, v, w):
        return self._www(Code.lei, u, v, w)

    def ler_u(self, u, v, w):
        return self._www(Code.ler_u, u, v, w)

    def lei_u(self, u, v, w):
        return self._www(Code.lei_u, u, v, w)

    def eqr(self, u, v, w):
        return self._www(Code.eqr, u, v, w)

    def eqi(self, u, v, w):
        return self._www(Code.eqi, u, v, w)

    def ger(self, u, v, w):
        return self._www(Code.ger, u, v, w)

    def gei(self, u, v, w):
        return self._www(Code.gei, u, v, w)

    def ger_u(self, u, v, w):
        return self._www(Code.ger_u, u, v, w)

    def gei_u(self, u, v, w):
        return self._www(Code.gei_u, u, v, w)

    def gtr(self, u, v, w):
        return self._www(Code.gtr, u, v, w)

    def gti(self, u, v, w):
        return self._www(Code.gti, u, v, w)

    def gtr_u(self, u, v, w):
        return self._www(Code.gtr_u, u, v, w)

    def gti_u(self, u, v, w):
        return self._www(Code.gti_u, u, v, w)

    def ner(self, u, v, w):
        return self._www(Code.ner, u, v, w)

    def nei(self, u, v, w):
        return self._www(Code.nei, u, v, w)

    def movr(self, u, v):
        return self._ww(Code.movr, u, v)

    def movi(self, u, v):
        return self._ww(Code.movi, u, v)

    def extr_c(self, u, v):
        return self._ww(Code.extr_c, u, v)

    def extr_uc(self, u, v):
        return self._ww(Code.extr_uc, u, v)

    def extr_s(self, u, v):
        return self._ww(Code.extr_s, u, v)

    def extr_us(self, u, v):
        return self._ww(Code.extr_us, u, v)

    def htonr_us(self, u, v):
        return self._ww(Code.htonr_us, u, v)

    def ntohr_us(self, u, v):
        return self._ww(Code.htonr_us, u, v)

    def htonr_ui(self, u, v):
        return self._ww(Code.htonr_ui, u, v)

    def ntohr_ui(self, u, v):
        return self._ww(Code.htonr_ui, u, v)

    def ldr_c(self, u, v):
        return self._ww(Code.ldr_c, u, v)

    def ldi_c(self, u, v):
        return self._wp(Code.ldi_c, u, v)

    def ldr_uc(self, u, v):
        return self._ww(Code.ldr_uc, u, v)

    def ldi_uc(self, u, v):
        return self._wp(Code.ldi_uc, u, v)

    def ldr_s(self, u, v):
        return self._ww(Code.ldr_s, u, v)

    def ldi_s(self, u, v):
        return self._wp(Code.ldi_s, u, v)

    def ldr_us(self, u, v):
        return self._ww(Code.ldr_us, u, v)

    def ldi_us(self, u, v):
        return self._wp(Code.ldi_us, u, v)

    def ldr_i(self, u, v):
        return self._ww(Code.ldr_i, u, v)

    def ldi_i(self, u, v):
        return self._wp(Code.ldi_i, u, v)

    def ldxr_c(self, u, v, w):
        return self._www(Code.ldxr_c, u, v, w)

    def ldxi_c(self, u, v, w):
        return self._www(Code.ldxi_c, u, v, w)

    def ldxr_uc(self, u, v, w):
        return self._www(Code.ldxr_uc, u, v, w)

    def ldxi_uc(self, u, v, w):
        return self._www(Code.ldxi_uc, u, v, w)

    def ldxr_s(self, u, v, w):
        return self._www(Code.ldxr_s, u, v, w)

    def ldxi_s(self, u, v, w):
        return self._www(Code.ldxi_s, u, v, w)

    def ldxr_us(self, u, v, w):
        return self._www(Code.ldxr_us, u, v, w)

    def ldxi_us(self, u, v, w):
        return self._www(Code.ldxi_us, u, v, w)

    def ldxr_i(self, u, v, w):
        return self._www(Code.ldxr_i, u, v, w)

    def ldxi_i(self, u, v, w):
        return self._www(Code.ldxi_i, u, v, w)

    def str_c(self, u, v):
        return self._ww(Code.str_c, u, v)

    def sti_c(self, u, v):
        return self._pw(Code.sti_c, u, v)

    def str_s(self, u, v):
        return self._ww(Code.str_s, u, v)

    def sti_s(self, u, v):
        return self._pw(Code.sti_s, u, v)

    def str_i(self, u, v):
        return self._ww(Code.str_i, u, v)

    def sti_i(self, u, v):
        return self._pw(Code.sti_i, u, v)

    def stxr_c(self, u, v, w):
        return self._www(Code.stxr_c, u, v, w)

    def stxi_c(self, u, v, w):
        return self._www(Code.stxi_c, u, v, w)

    def stxr_s(self, u, v, w):
        return self._www(Code.stxr_s, u, v, w)

    def stxi_s(self, u, v, w):
        return self._www(Code.stxi_s, u, v, w)

    def stxr_i(self, u, v, w):
        return self._www(Code.stxr_i, u, v, w)

    def stxi_i(self, u, v, w):
        return self._www(Code.stxi_i, u, v, w)

    def bltr(self, v, w):
        return self._pww(Code.bltr, None, v, w)

    def blti(self, v, w):
        return self._pww(Code.blti, None, v, w)

    def bltr_u(self, v, w):
        return self._pww(Code.bltr_u, None, v, w)

    def blti_u(self, v, w):
        return self._pww(Code.blti_u, None, v, w)

    def bler(self, v, w):
        return self._pww(Code.bler, None, v, w)

    def blei(self, v, w):
        return self._pww(Code.blei, None, v, w)

    def bler_u(self, v, w):
        return self._pww(Code.bler_u, None, v, w)

    def blei_u(self, v, w):
        return self._pww(Code.blei_u, None, v, w)

    def beqr(self, v, w):
        return self._pww(Code.beqr, None, v, w)

    def beqi(self, node, v, w):
        return self._pww(Code.beqi, node.value, v, w)

    def bger(self, node, v, w):
        return self._pww(Code.bger, node.value, v, w)

    def bgei(self, node, v, w):
        return self._pww(Code.bgei, node.value, v, w)

    def bger_u(self, node, v, w):
        return self._pww(Code.bger_u, node.value, v, w)

    def bgei_u(self, node, v, w):
        return self._pww(Code.bgei_u, node.value, v, w)

    def bgtr(self, node, v, w):
        return self._pww(Code.bgtr, node.value, v, w)

    def bgti(self, node, v, w):
        return self._pww(Code.bgti, node.value, v, w)

    def bgtr_u(self, node, v, w):
        return self._pww(Code.bgtr_u, node.value, v, w)

    def bgti_u(self, node, v, w):
        return self._pww(Code.bgti_u, node.value, v, w)

    def bner(self, node, v, w):
        return self._pww(Code.bner, node.value, v, w)

    def bnei(self, node, v, w):
        return self._pww(Code.bnei, node.value, v, w)

    def bmsr(self, node, v, w):
        return self._pww(Code.bmsr, node.value, v, w)

    def bmsi(self, node, v, w):
        return self._pww(Code.bmsi, node.value, v, w)

    def bmcr(self, node, v, w):
        return self._pww(Code.bmcr, node.value, v, w)

    def bmci(self, node, v, w):
        return self._pww(Code.bmci, node.value, v, w)

    def boaddr(self, node, v, w):
        return self._pww(Code.boaddr, node.value, v, w)

    def boaddi(self, node, v, w):
        return self._pww(Code.boaddi, node.value, v, w)

    def boaddr_u(self, node, v, w):
        return self._pww(Code.boaddr_u, node.value, v, w)

    def boaddi_u(self, node, v, w):
        return self._pww(Code.boaddi_u, node.value, v, w)

    def bxaddr(self, node, v, w):
        return self._pww(Code.bxaddr, node.value, v, w)

    def bxaddi(self, node, v, w):
        return self._pww(Code.bxaddi, node.value, v, w)

    def bxaddr_u(self, node, v, w):
        return self._pww(Code.bxaddr_u, node.value, v, w)

    def bxaddi_u(self, node, v, w):
        return self._pww(Code.bxaddi_u, node.value, v, w)

    def bosubr(self, node, v, w):
        return self._pww(Code.bosubr, node.value, v, w)

    def bosubi(self, node, v, w):
        return self._pww(Code.bosubi, node.value, v, w)

    def bosubr_u(self, node, v, w):
        return self._pww(Code.bosubr_u, node.value, v, w)

    def bosubi_u(self, node, v, w):
        return self._pww(Code.bosubi_u, node.value, v, w)

    def bxsubr(self, node, v, w):
        return self._pww(Code.bxsubr, node.value, v, w)

    def bxsubi(self, node, v, w):
        return self._pww(Code.bxsubi, node.value, v, w)

    def bxsubr_u(self, node, v, w):
        return self._pww(Code.bxsubr_u, node.value, v, w)

    def bxsubi_u(self, node, v, w):
        return self._pww(Code.bxsubi_u, node.value, v, w)

    def jmpr(self, u):
        return self._w(Code.jmpr, u)

    def jmpi(self, immediate):
        return self._p(Code.jmpi, None)

    def callr(self, u):
        return self._w(Code.callr, u)

    def calli(self, u):
        return self._p(Code.calli, u)

    def prepare(self, ):
        return self.lib._jit_prepare(self.state)

    def pushargr(self, u):
        return self.lib._jit_pushargr(self.state, u)

    def pushargi(self, u):
        self._assert_prolog()
        return self.lib._jit_pushargi(self.state, u)

    def finishr(self, u):
        return self.lib._jit_finishr(self.state, u)

    def finishi(self, u):
        return self.lib._jit_finishi(self.state, u)

    def ret(self, ):
        return self.lib._jit_ret(self.state)

    def retr(self, u):
        return self.lib._jit_retr(self.state, u)

    def reti(self, u):
        return self.lib._jit_reti(self.state, u)

    def retval(self, u):
        if __wordsize == 32:
            return self.retval_i(u)
        else:
            return self.retval_l(u)

    def retval_f(self, u):
        return self.lib._jit_retval_f(self.state, u)

    def retval_l(self, u):
        return self.lib._jit_retval_l(self.state, u)

    def retval_d(self, u):
        return self._jit_retval_d(self.state, u)

    def retval_c(self, u):
        return self.lib._jit_retval_c(self.state, u)

    def retval_uc(self, u):
        return self.lib._jit_retval_uc(self.state, u)

    def retval_s(self, u):
        return self.lib._jit_retval_s(self.state, u)

    def retval_us(self, u):
        return self.lib._jit_retval_us(self.state, u)

    def retval_i(self, u):
        return self.lib._jit_retval_i(self.state, u)

    def epilog(self, ):
        self._assert_prolog()
        self._prolog = False
        return self.lib._jit_epilog(self.state)

    def arg_f(self, ):
        return Node(self._jit_arg_f(self.state))

    def getarg_f(self, u, v):
        return self.lib._jit_getarg_f(self.state, u, v)

    def putargr_f(self, u, v):
        return self.lib._jit_putargr_f(self.state, u, v)

    def putargi_f(self, u, v):
        return self.lib._jit_putargi_f(self.state, u, v)

    def addr_f(self, u, v, w):
        return self.lib._www(Code.addr_f, u, v, w)

    def addi_f(self, u, v, w):
        return self.lib._wwf(Code.addi_f, u, v, w)

    def subr_f(self, u, v, w):
        return self.lib._www(Code.subr_f, u, v, w)

    def subi_f(self, u, v, w):
        return self.lib._wwf(Code.subi_f, u, v, w)

    def rsbr_f(self, u, v, w):
        return self.jit_subr_f(u, w, v)

    def rsbi_f(self, u, v, w):
        return self._wwf(Code.rsbi_f, u, v, w)

    def mulr_f(self, u, v, w):
            return self._www(Code.mulr_f, u, v, w)

    def muli_f(self, u, v, w):
            return self._wwf(Code.muli_f, u, v, w)

    def divr_f(self, u, v, w):
            return self._www(Code.divr_f, u, v, w)

    def divi_f(self, u, v, w):
            return self._wwf(Code.divi_f, u, v, w)

    def negr_f(self, u, v):
            return self._ww(Code.negr_f, u, v)

    def absr_f(self, u, v):
            return self._ww(Code.absr_f, u, v)

    def sqrtr_f(self, u, v):
            return self._ww(Code.sqrtr_f, u, v)

    def ltr_f(self, u, v, w):
            return self._www(Code.ltr_f, u, v, w)

    def lti_f(self, u, v, w):
            return self._wwf(Code.lti_f, u, v, w)

    def ler_f(self, u, v, w):
            return self._www(Code.ler_f, u, v, w)

    def lei_f(self, u, v, w):
            return self._wwf(Code.lei_f, u, v, w)

    def eqr_f(self, u, v, w):
            return self._www(Code.eqr_f, u, v, w)

    def eqi_f(self, u, v, w):
            return self._wwf(Code.eqi_f, u, v, w)

    def ger_f(self, u, v, w):
            return self._www(Code.ger_f, u, v, w)

    def gei_f(self, u, v, w):
            return self._wwf(Code.gei_f, u, v, w)

    def gtr_f(self, u, v, w):
            return self._www(Code.gtr_f, u, v, w)

    def gti_f(self, u, v, w):
            return self._wwf(Code.gti_f, u, v, w)

    def ner_f(self, u, v, w):
            return self._www(Code.ner_f, u, v, w)

    def nei_f(self, u, v, w):
            return self._wwf(Code.nei_f, u, v, w)

    def unltr_f(self, u, v, w):
            return self._www(Code.unltr_f, u, v, w)

    def unlti_f(self, u, v, w):
            return self._wwf(Code.unlti_f, u, v, w)

    def unler_f(self, u, v, w):
            return self._www(Code.unler_f, u, v, w)

    def unlei_f(self, u, v, w):
            return self._wwf(Code.unlei_f, u, v, w)

    def uneqr_f(self, u, v, w):
            return self._www(Code.uneqr_f, u, v, w)

    def uneqi_f(self, u, v, w):
            return self._wwf(Code.uneqi_f, u, v, w)

    def unger_f(self, u, v, w):
            return self._www(Code.unger_f, u, v, w)

    def ungei_f(self, u, v, w):
            return self._wwf(Code.ungei_f, u, v, w)

    def ungtr_f(self, u, v, w):
            return self._www(Code.ungtr_f, u, v, w)

    def ungti_f(self, u, v, w):
            return self._wwf(Code.ungti_f, u, v, w)

    def ltgtr_f(self, u, v, w):
            return self._www(Code.ltgtr_f, u, v, w)

    def ltgti_f(self, u, v, w):
            return self._wwf(Code.ltgti_f, u, v, w)

    def ordr_f(self, u, v, w):
            return self._www(Code.ordr_f, u, v, w)

    def ordi_f(self, u, v, w):
            return self._wwf(Code.ordi_f, u, v, w)

    def unordr_f(self, u, v, w):
            return self._www(Code.unordr_f, u, v, w)

    def unordi_f(self, u, v, w):
            return self._wwf(Code.unordi_f, u, v, w)

    def truncr_f_i(self, u, v):
            return self._ww(Code.truncr_f_i, u, v)

    def extr_f(self, u, v):
            return self._ww(Code.extr_f, u, v)

    def extr_d_f(self, u, v):
            return self._ww(Code.extr_d_f, u, v)

    def movr_f(self, u, v):
            return self._ww(Code.movr_f, u, v)

    def movi_f(self, u, v):
            return self._wf(Code.movi_f, u, v)

    def ldr_f(self, u, v):
            return self._ww(Code.ldr_f, u, v)

    def ldi_f(self, u, v):
            return self._wp(Code.ldi_f, u, v)

    def ldxr_f(self, u, v, w):
            return self._www(Code.ldxr_f, u, v, w)

    def ldxi_f(self, u, v, w):
            return self._www(Code.ldxi_f, u, v, w)

    def str_f(self, u, v):
            return self._ww(Code.str_f, u, v)

    def sti_f(self, u, v):
            return self._pw(Code.sti_f, u, v)

    def stxr_f(self, u, v, w):
            return self._www(Code.stxr_f, u, v, w)

    def stxi_f(self, u, v, w):
            return self._www(Code.stxi_f, u, v, w)

    def bltr_f(self, node, v, w):
            return self._pww(Code.bltr_f, node.value, v, w)

    def blti_f(self, node, v, w):
            return self._pwf(Code.blti_f, node.value, v, w)

    def bler_f(self, node, v, w):
            return self._pww(Code.bler_f, node.value, v, w)

    def blei_f(self, node, v, w):
            return self._pwf(Code.blei_f, node.value, v, w)

    def beqr_f(self, node, v, w):
            return self._pww(Code.beqr_f, node.value, v, w)

    def beqi_f(self, node, v, w):
            return self._pwf(Code.beqi_f, node.value, v, w)

    def bger_f(self, node, v, w):
            return self._pww(Code.bger_f, node.value, v, w)

    def bgei_f(self, node, v, w):
            return self._pwf(Code.bgei_f, node.value, v, w)

    def bgtr_f(self, node, v, w):
            return self._pww(Code.bgtr_f, node.value, v, w)

    def bgti_f(self, node, v, w):
            return self._pwf(Code.bgti_f, node.value, v, w)

    def bner_f(self, node, v, w):
            return self._pww(Code.bner_f, node.value, v, w)

    def bnei_f(self, node, v, w):
            return self._pwf(Code.bnei_f, node.value, v, w)

    def bunltr_f(self, node, v, w):
            return self._pww(Code.bunltr_f, node.value, v, w)

    def bunlti_f(self, node, v, w):
            return self._pwf(Code.bunlti_f, node.value, v, w)

    def bunler_f(self, node, v, w):
            return self._pww(Code.bunler_f, node.value, v, w)

    def bunlei_f(self, node, v, w):
            return self._pwf(Code.bunlei_f, node.value, v, w)

    def buneqr_f(self, node, v, w):
            return self._pww(Code.buneqr_f, node.value, v, w)

    def buneqi_f(self, node, v, w):
            return self._pwf(Code.buneqi_f, node.value, v, w)

    def bunger_f(self, node, v, w):
            return self._pww(Code.bunger_f, node.value, v, w)

    def bungei_f(self, node, v, w):
            return self._pwf(Code.bungei_f, node.value, v, w)

    def bungtr_f(self, node, v, w):
            return self._pww(Code.bungtr_f, node.value, v, w)

    def bungti_f(self, node, v, w):
            return self._pwf(Code.bungti_f, node.value, v, w)

    def bltgtr_f(self, node, v, w):
            return self._pww(Code.bltgtr_f, node.value, v, w)

    def bltgti_f(self, node, v, w):
            return self._pwf(Code.bltgti_f, node.value, v, w)

    def bordr_f(self, node, v, w):
            return self._pww(Code.bordr_f, node.value, v, w)

    def bordi_f(self, node, v, w):
            return self._pwf(Code.bordi_f, node.value, v, w)

    def bunordr_f(self, node, v, w):
            return self._pww(Code.bunordr_f, node.value, v, w)

    def bunordi_f(self, node, v, w):
            return self._pwf(Code.bunordi_f, node.value, v, w)

    def pushargr_f(self, u):
            return self.lib._jit_pushargr_f(self.state, u)

    def pushargi_f(self, u):
        return self.lib._jit_pushargi_f(self.state, u)

    def retr_f(self, u):
        return self.lib._jit_retr_f(self.state, u)

    def reti_f(self, u):
        return self.lib._jit_reti_f(self.state, u)

    def arg_d(self):
        return Node(self._jit_arg_d(self.state))

    def getarg_d(self, u, v):
            return self.lib._jit_getarg_d(self.state, u, v)

    def putargr_d(self, u, v):
        return self.lib._jit_putargr_d(self.state, u, v)

    def putargi_d(self, u, v):
        return self.lib._jit_putargi_d(self.state, u, v)

    def addr_d(self, u, v, w):
        return self._www(Code.addr_d, u, v, w)

    def addi_d(self, u, v, w):
        return self._wwd(Code.addi_d, u, v, w)

    def subr_d(self, u, v, w):
        return self._www(Code.subr_d, u, v, w)

    def subi_d(self, u, v, w):
        return self._wwd(Code.subi_d, u, v, w)

    def rsbr_d(self, u, v, w):
        return self.jit_subr_d(u, w, v)

    def rsbi_d(self, u, v, w):
        return self._wwd(Code.rsbi_d, u, v, w)

    def mulr_d(self, u, v, w):
        return self._www(Code.mulr_d, u, v, w)

    def muli_d(self, u, v, w):
        return self._wwd(Code.muli_d, u, v, w)

    def divr_d(self, u, v, w):
        return self._www(Code.divr_d, u, v, w)

    def divi_d(self, u, v, w):
        return self._wwd(Code.divi_d, u, v, w)

    def negr_d(self, u, v):
        return self._ww(Code.negr_d, u, v)

    def absr_d(self, u, v):
        return self._ww(Code.absr_d, u, v)

    def sqrtr_d(self, u, v):
        return self._ww(Code.sqrtr_d, u, v)

    def ltr_d(self, u, v, w):
        return self._www(Code.ltr_d, u, v, w)

    def lti_d(self, u, v, w):
        return self._wwd(Code.lti_d, u, v, w)

    def ler_d(self, u, v, w):
        return self._www(Code.ler_d, u, v, w)

    def lei_d(self, u, v, w):
        return self._wwd(Code.lei_d, u, v, w)

    def eqr_d(self, u, v, w):
        return self._www(Code.eqr_d, u, v, w)

    def eqi_d(self, u, v, w):
        return self._wwd(Code.eqi_d, u, v, w)

    def ger_d(self, u, v, w):
        return self._www(Code.ger_d, u, v, w)

    def gei_d(self, u, v, w):
        return self._wwd(Code.gei_d, u, v, w)

    def gtr_d(self, u, v, w):
        return self._www(Code.gtr_d, u, v, w)

    def gti_d(self, u, v, w):
        return self._wwd(Code.gti_d, u, v, w)

    def ner_d(self, u, v, w):
        return self._www(Code.ner_d, u, v, w)

    def nei_d(self, u, v, w):
        return self._wwd(Code.nei_d, u, v, w)

    def unltr_d(self, u, v, w):
        return self._www(Code.unltr_d, u, v, w)

    def unlti_d(self, u, v, w):
        return self._wwd(Code.unlti_d, u, v, w)

    def unler_d(self, u, v, w):
        return self._www(Code.unler_d, u, v, w)

    def unlei_d(self, u, v, w):
        return self._wwd(Code.unlei_d, u, v, w)

    def uneqr_d(self, u, v, w):
        return self._www(Code.uneqr_d, u, v, w)

    def uneqi_d(self, u, v, w):
        return self._wwd(Code.uneqi_d, u, v, w)

    def unger_d(self, u, v, w):
        return self._www(Code.unger_d, u, v, w)

    def ungei_d(self, u, v, w):
        return self._wwd(Code.ungei_d, u, v, w)

    def ungtr_d(self, u, v, w):
        return self._www(Code.ungtr_d, u, v, w)

    def ungti_d(self, u, v, w):
        return self._wwd(Code.ungti_d, u, v, w)

    def ltgtr_d(self, u, v, w):
        return self._www(Code.ltgtr_d, u, v, w)

    def ltgti_d(self, u, v, w):
        return self._wwd(Code.ltgti_d, u, v, w)

    def ordr_d(self, u, v, w):
        return self._www(Code.ordr_d, u, v, w)

    def ordi_d(self, u, v, w):
        return self._wwd(Code.ordi_d, u, v, w)

    def unordr_d(self, u, v, w):
        return self._www(Code.unordr_d, u, v, w)

    def unordi_d(self, u, v, w):
        return self._wwd(Code.unordi_d, u, v, w)

    def truncr_d_i(self, u, v):
        return self._ww(Code.truncr_d_i, u, v)

    def extr_d(self, u, v):
        return self._ww(Code.extr_d, u, v)

    def extr_f_d(self, u, v):
        return self._ww(Code.extr_f_d, u, v)

    def movr_d(self, u, v):
        return self._ww(Code.movr_d, u, v)

    def movi_d(self, u, v):
        return self._wd(Code.movi_d, u, v)

    def ldr_d(self, u, v):
        return self._ww(Code.ldr_d, u, v)

    def ldi_d(self, u, v):
        return self._wp(Code.ldi_d, u, v)

    def ldxr_d(self, u, v, w):
        return self._www(Code.ldxr_d, u, v, w)

    def ldxi_d(self, u, v, w):
        return self._www(Code.ldxi_d, u, v, w)

    def str_d(self, u, v):
        return self._ww(Code.str_d, u, v)

    def sti_d(self, u, v):
        return self._pw(Code.sti_d, u, v)

    def stxr_d(self, u, v, w):
        return self._www(Code.stxr_d, u, v, w)

    def stxi_d(self, u, v, w):
        return self._www(Code.stxi_d, u, v, w)

    def bltr_d(self, node, v, w):
        return self._pww(Code.bltr_d, node.value, v, w)

    def blti_d(self, node, v, w):
        return self._pwd(Code.blti_d, node.value, v, w)

    def bler_d(self, node, v, w):
        return self._pww(Code.bler_d, node.value, v, w)

    def blei_d(self, node, v, w):
        return self._pwd(Code.blei_d, node.value, v, w)

    def beqr_d(self, node, v, w):
        return self._pww(Code.beqr_d, node.value, v, w)

    def beqi_d(self, node, v, w):
        return self._pwd(Code.beqi_d, node.value, v, w)

    def bger_d(self, node, v, w):
        return self._pww(Code.bger_d, node.value, v, w)

    def bgei_d(self, node, v, w):
        return self._pwd(Code.bgei_d, node.value, v, w)

    def bgtr_d(self, node, v, w):
        return self._pww(Code.bgtr_d, node.value, v, w)

    def bgti_d(self, node, v, w):
        return self._pwd(Code.bgti_d, node.value, v, w)

    def bner_d(self, node, v, w):
        return self._pww(Code.bner_d, node.value, v, w)

    def bnei_d(self, node, v, w):
        return self._pwd(Code.bnei_d, node.value, v, w)

    def bunltr_d(self, node, v, w):
        return self._pww(Code.bunltr_d, node.value, v, w)

    def bunlti_d(self, node, v, w):
        return self._pwd(Code.bunlti_d, node.value, v, w)

    def bunler_d(self, node, v, w):
        return self._pww(Code.bunler_d, node.value, v, w)

    def bunlei_d(self, node, v, w):
        return self._pwd(Code.bunlei_d, node.value, v, w)

    def buneqr_d(self, node, v, w):
        return self._pww(Code.buneqr_d, node.value, v, w)

    def buneqi_d(self, node, v, w):
        return self._pwd(Code.buneqi_d, node.value, v, w)

    def bunger_d(self, node, v, w):
        return self._pww(Code.bunger_d, node.value, v, w)

    def bungei_d(self, node, v, w):
        return self._pwd(Code.bungei_d, node.value, v, w)

    def bungtr_d(self, node, v, w):
        return self._pww(Code.bungtr_d, node.value, v, w)

    def bungti_d(self, node, v, w):
        return self._pwd(Code.bungti_d, node.value, v, w)

    def bltgtr_d(self, node, v, w):
        return self._pww(Code.bltgtr_d, node.value, v, w)

    def bltgti_d(self, node, v, w):
        return self._pwd(Code.bltgti_d, node.value, v, w)

    def bordr_d(self, node, v, w):
        return self._pww(Code.bordr_d, node.value, v, w)

    def bordi_d(self, node, v, w):
        return self._pwd(Code.bordi_d, node.value, v, w)

    def bunordr_d(self, node, v, w):
        return self._pww(Code.bunordr_d, node.value, v, w)

    def bunordi_d(self, node, v, w):
        return self._pwd(Code.bunordi_d, node.value, v, w)

    def pushargr_d(self, u):
        return self._jit_pushargr_d(self.state, u)

    def pushargi_d(self, u):
        return self._jit_pushargi_d(self.state, u)

    def retr_d(self, u):
        return self._jit_retr_d(self.state, u)

    def reti_d(self, u):
        return self._jit_reti_d(self.state, u)

    def movr_w_f(self, u, v):
        return self._ww(Code.movr_w_f, u, v)

    def movr_ww_d(self, u, v, w):
        return self._www(Code.movr_ww_d, u, v, w)

    def movr_w_d(self, u, v):
        return self._ww(Code.movr_w_d, u, v)

    def movr_f_w(self, u, v):
        return self._ww(Code.movr_f_w, u, v)

    def movi_f_w(self, u, v):
        return self._wf(Code.movi_f_w, u, v)

    def movr_d_ww(self, u, v, w):
        return self._www(Code.movr_d_ww, u, v, w)

    def movi_d_ww(self, u, v, w):
        return self._wwd(Code.movi_d_ww, u, v, w)

    def movr_d_w(self, u, v):
        return self._ww(Code.movr_d_w, u, v)

    def movi_d_w(self, u, v):
        return self._wd(Code.movi_d_w, u, v)

    def forward_p(self, u):
        return self.lib._jit_forward_p(self.state, u)

    def indirect_p(self, u):
        return self.lib._jit_indirect_p(self.state, u)

    def target_p(self, u):
        return self.lib._jit_target_p(self.state, u)

    def patch(self, u):
        return self.lib._jit_patch(self.state, u)

    def patch_at(self, u, v):
        return self.lib._jit_patch_at(self.state, u.value, v.value)

    def patch_abs(self, u, v):
        return self.lib._jit_patch_abs(self.state, u, v)

    def realize(self, ):
        return self.lib._jit_realize(self.state)

    def get_code(self, u):
        return Pointer(self.lib._jit_get_code(self.state, u))

    def set_code(self, u, v):
        return self.lib._jit_set_code(self.state, u, v)

    def get_data(self, u, v):
        return Pointer(self.lib._jit_get_data(self.state, u, v))

    def set_data(self, u, v, w):
        return self.lib._jit_set_data(self.state, u, v, w)

    def frame(self, u):
        return self.lib._jit_frame(self.state, u)

    def tramp(self, u):
        return self.lib._jit_tramp(self.state, u)

    def print_(self):
        return self.lib._jit_print(self.state)

    def arg_register_p(self, u):
        return self.lib._jit_arg_register_p(self.state, u)

    def callee_save_p(self, u):
        return self.lib._jit_callee_save_p(self.state, u)

    def pointer_p(self, u):
        return self.lib._jit_pointer_p(self.state, u)

    def get_note(self, n, u, v, w):
        return self.lib._jit_get_note(self.state, n, u, v, w)

    def disassemble(self, ):
        return self.lib._jit_disassemble(self.state)
