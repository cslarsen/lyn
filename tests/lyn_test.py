from lyn import Register, Lightning
import ctypes
import lyn
import random
import unittest

class TestLyn(unittest.TestCase):
    def setUp(self):
        self.lyn = Lightning()

    def tearDown(self):
        self.lyn.release()

    def test_nested_states(self):
        with self.lyn.state() as a:
            self.assertFalse(a is None)
            with self.lyn.state() as b:
                self.assertFalse(b is None)
                self.assertNotEqual(a, b)

    def test_state(self):
        with self.lyn.state() as a:
           self.assertFalse(a is None)

    def test_empty_code(self):
        with self.lyn.state() as jit:
            jit.prolog()
            code_ptr = jit.emit()
            self.assertFalse(code_ptr is None)

    def test_single_instruction(self):
        with self.lyn.state() as jit:
            jit.prolog()
            jit.movi(Register.v0, 123)
            code_ptr = jit.emit()
            self.assertFalse(code_ptr is None)

    def test_addi(self):
        with self.lyn.state() as jit:
            jit.prolog()
            jit.movi(Register.v1, 22)
            jit.addi(Register.v2, Register.v1, 33)
            jit.retr(Register.v2)
            f = jit.emit_function(lyn.word_t)
            self.assertEqual(f(), 55)

    def test_addr(self):
        with self.lyn.state() as jit:
            jit.prolog()
            jit.movi(Register.v1, 22)
            jit.movi(Register.v2, 44)
            jit.addr(Register.v3, Register.v1, Register.v2)
            jit.retr(Register.v3)
            f = jit.emit_function(lyn.word_t)
            self.assertEqual(f(), 66)

    def test_execution(self):
        with self.lyn.state() as jit:
            # Create a function that returns 123
            jit.prolog()
            jit.movi(Register.v0, 123)
            jit.movi(Register.v1, 456)
            jit.retr(Register.v0)
            code = jit.emit()
            self.assertFalse(code is None)
            self.assertFalse(code.value is None)

            make_func = ctypes.CFUNCTYPE(ctypes.c_int)
            func = make_func(code.value)
            result = func()
            self.assertTrue(result is not None)
            self.assertTrue(isinstance(result, int))
            self.assertEqual(result, 123)

    def test_incr(self):
        with self.lyn.state() as jit:
            jit.prolog()
            num = jit.arg()
            jit.getarg(Register.r0, num)
            jit.addi(Register.r0, Register.r0, 1)
            jit.retr(Register.r0)

            incr = jit.emit_function(lyn.word_t, [lyn.word_t])

            for n in range(-1000, 1000):
                self.assertEqual(incr(n), n+1)

            bits = lyn.wordsize
            self.assertEqual(incr(2**(bits-1)-2), 2**(bits-1)-1)
            self.assertEqual(incr(2**(bits-1)-1), -2**(bits-1))

    def test_roundtrip_mul(self):
        with self.lyn.state() as jit:
            jit.prolog()
            n = jit.arg()
            jit.getarg(Register.r0, n)
            jit.muli(Register.r0, Register.r0, 1)
            jit.retr(Register.r0)

            mul1 = jit.emit_function(lyn.word_t, [lyn.word_t])
            bits = lyn.wordsize

            for n in [0, 1, -1, 2**(bits-1)-1, -2**(bits-1)]:
                self.assertEqual(mul1(n), n)

    def test_mul2(self):
        with self.lyn.state() as jit:
            jit.prolog()
            num = jit.arg()
            jit.getarg(Register.r0, num)
            jit.muli(Register.r0, Register.r0, 2)
            jit.retr(Register.r0)

            mul2 = jit.emit_function(lyn.word_t, [lyn.word_t])

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
        with self.lyn.state() as jit:
            bits = lyn.wordsize

            for number in [0, 1, -1, 2**(bits-1)-1, -2**(bits-1)]:
                with self.lyn.state() as jit:
                    jit.prolog()
                    jit.movi(Register.r0, number)
                    jit.retr(Register.r0)
                    func = jit.emit_function(lyn.word_t, [])
                    self.assertEqual(func(), number)

    def test_roundtrip_arg(self):
        with self.lyn.state() as jit:
            bits = lyn.wordsize

            with self.lyn.state() as jit:
                jit.prolog()
                num = jit.arg()
                jit.getarg(Register.r0, num)
                jit.retr(Register.r0)
                func = jit.emit_function(lyn.word_t, [lyn.word_t])

                for n in [0, 1, -1, 2**(bits-1)-1, -2**(bits-1)]:
                    self.assertEqual(func(n), n)

    def test_sequential_states(self):
        with self.lyn.state() as a:
            self.assertFalse(a is None)

        with self.lyn.state() as b:
            self.assertFalse(a is None)
            self.assertFalse(b is None)

if __name__ == "__main__":
    unittest.main()
