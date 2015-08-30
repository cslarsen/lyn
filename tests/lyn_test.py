from lyn import Register, Lightning
import ctypes
import lyn
import random
import sys
import unittest


class TestLyn(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lyn = Lightning()

    @classmethod
    def tearDownClass(cls):
        cls.lyn.release()

    def setUp(self):
        if sys.version.startswith("2.6"):
            self.lyn = Lightning()
        self.jit = self.lyn.state()

    def tearDown(self):
        self.jit.clear()
        self.jit.release()
        if sys.version.startswith("2.6"):
            self.lyn.release()

    def test_nested_states(self):
        self.assertFalse(self.jit is None)
        with self.lyn.state() as b:
            self.assertFalse(b is None)
            self.assertNotEqual(self.jit, b)

    def test_empty_code(self):
        self.jit.prolog()
        code_ptr = self.jit.emit()
        self.assertFalse(code_ptr is None)

    def test_single_instruction(self):
        self.jit.prolog()
        self.jit.movi(Register.v0, 123)
        code_ptr = self.jit.emit()
        self.assertFalse(code_ptr is None)

    def test_addi(self):
        self.jit.prolog()
        self.jit.movi(Register.v1, 22)
        self.jit.addi(Register.v2, Register.v1, 33)
        self.jit.retr(Register.v2)
        f = self.jit.emit_function(lyn.word_t)
        self.assertEqual(f(), 55)

    def test_addr(self):
        self.jit.prolog()
        self.jit.movi(Register.v1, 22)
        self.jit.movi(Register.v2, 44)
        self.jit.addr(Register.v3, Register.v1, Register.v2)
        self.jit.retr(Register.v3)
        f = self.jit.emit_function(lyn.word_t)
        self.assertEqual(f(), 66)

    def test_execution(self):
        # Create a function that returns 123
        self.jit.prolog()
        self.jit.movi(Register.v0, 123)
        self.jit.movi(Register.v1, 456)
        self.jit.retr(Register.v0)
        code = self.jit.emit()
        self.assertFalse(code is None)
        self.assertFalse(code.value is None)

        make_func = ctypes.CFUNCTYPE(ctypes.c_int)
        func = make_func(code.value)
        result = func()
        self.assertTrue(result is not None)
        self.assertTrue(isinstance(result, int))
        self.assertEqual(result, 123)

    def test_incr(self):
        self.jit.prolog()
        num = self.jit.arg()
        self.jit.getarg(Register.r0, num)
        self.jit.addi(Register.r0, Register.r0, 1)
        self.jit.retr(Register.r0)

        incr = self.jit.emit_function(lyn.word_t, [lyn.word_t])

        for n in range(-1000, 1000):
            self.assertEqual(incr(n), n+1)

        bits = lyn.wordsize
        self.assertEqual(incr(2**(bits-1)-2), 2**(bits-1)-1)
        self.assertEqual(incr(2**(bits-1)-1), -2**(bits-1))

    def test_roundtrip_mul(self):
        self.jit.prolog()
        n = self.jit.arg()
        self.jit.getarg(Register.r0, n)
        self.jit.muli(Register.r0, Register.r0, 1)
        self.jit.retr(Register.r0)

        mul1 = self.jit.emit_function(lyn.word_t, [lyn.word_t])
        bits = lyn.wordsize

        for n in [0, 1, -1, 2**(bits-1)-1, -2**(bits-1)]:
            self.assertEqual(mul1(n), n)

    def test_mul2(self):
        self.jit.prolog()
        num = self.jit.arg()
        self.jit.getarg(Register.r0, num)
        self.jit.muli(Register.r0, Register.r0, 2)
        self.jit.retr(Register.r0)

        mul2 = self.jit.emit_function(lyn.word_t, [lyn.word_t])

        for n in range(-1000, 1000):
            self.assertEqual(mul2(n), 2*n)

        # Test again with random numbers
        bits = lyn.wordsize
        hmin = (-2**(bits-1))//2
        hmax = (2**(bits-1)-1)//2

        self.assertEqual(mul2(hmin), 2*hmin)
        self.assertEqual(mul2(hmax), 2*hmax)

        for _ in range(1000):
            n = random.randint(-2**(bits-1)//2, (2**(bits-1)-1)//2)
            self.assertEqual(mul2(n), n*2)

    def test_roundtrip_static(self):
        bits = lyn.wordsize

        for number in [0, 1, -1, 2**(bits-1)-1, -2**(bits-1)]:
            with self.lyn.state() as jit:
                jit.prolog()
                jit.movi(Register.r0, number)
                jit.retr(Register.r0)
                func = jit.emit_function(lyn.word_t, [])
                self.assertEqual(func(), number)

    def test_roundtrip_arg(self):
        bits = lyn.wordsize
        self.jit.prolog()
        num = self.jit.arg()
        self.jit.getarg(Register.r0, num)
        self.jit.retr(Register.r0)
        func = self.jit.emit_function(lyn.word_t, [lyn.word_t])

        for n in [0, 1, -1, 2**(bits-1)-1, -2**(bits-1)]:
            self.assertEqual(func(n), n)

    def test_strlen(self):
        libc = self.lyn.load("c")
        self.jit.prolog()
        self.jit.getarg(Register.r0, self.jit.arg())
        self.jit.pushargr(Register.r0)
        self.jit.finishi(libc.strlen)
        self.jit.retval(Register.r0)
        self.jit.retr(Register.r0)
        self.jit.epilog()

        strlen = self.jit.emit_function(lyn.word_t, [lyn.char_p])

        self.assertEqual(strlen(""), 0)
        self.assertEqual(strlen("h"), 1)
        self.assertEqual(strlen("he"), 2)
        self.assertEqual(strlen("hello"), 5)

    def test_sequential_states(self):
        self.assertFalse(self.jit is None)

        with self.lyn.state() as a:
            self.assertFalse(a is None)

        with self.lyn.state() as b:
            self.assertFalse(a is None)
            self.assertFalse(b is None)

    def test_forward_branch(self):
        self.jit.prolog()

        arg = self.jit.arg()
        self.jit.getarg(Register.r0, arg)

        true = self.jit.forward()
        self.jit.andi(Register.r0, Register.r0, 1)
        jump = self.jit.beqi(true, Register.r0, 1)
        self.jit.patch_at(jump, true)

        # False
        self.jit.reti(123)

        # True
        self.jit.link(true)
        self.jit.reti(456)

        self.jit.epilog()

        odd = self.jit.emit_function(lyn.word_t, [lyn.word_t])
        for n in range(100):
            self.assertEqual(odd(n), 456 if (n & 1) else 123)

    def test_prolog_guard(self):
        if sys.version.startswith("2.6"):
            self.assertRaises(lyn.LynError, self.jit.name, "foo")
        else:
            with self.assertRaises(lyn.LynError):
                self.jit.name("foo")


if __name__ == "__main__":
    unittest.main()
