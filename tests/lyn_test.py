import ctypes
import lyn
import unittest

class TestLyn(unittest.TestCase):
    def setUp(self):
        self.lyn = lyn.Lightning()

    def test_nested_states(self):
        with self.lyn.state() as a:
            self.assertIsNotNone(a)
            with self.lyn.state() as b:
                self.assertIsNotNone(b)
                self.assertNotEqual(a, b)

    def test_state(self):
        with self.lyn.state() as a:
           self.assertIsNotNone(a)

    def test_empty_code(self):
        with self.lyn.state() as jit:
            jit.prolog()
            code_ptr = jit.emit()
            self.assertIsNotNone(code_ptr)

    def test_single_instruction(self):
        with self.lyn.state() as jit:
            jit.prolog()
            jit.movi(lyn.Register.v0, 123)
            code_ptr = jit.emit()
            self.assertIsNotNone(code_ptr)

    def test_addi(self):
        with self.lyn.state() as jit:
            jit.prolog()
            jit.movi(lyn.Register.v1, 22)
            jit.addi(lyn.Register.v2, lyn.Register.v1, 33)
            jit.retr(lyn.Register.v2)
            f = jit.emit_function()
            self.assertEqual(f(), 55)

    def test_addr(self):
        with self.lyn.state() as jit:
            jit.prolog()
            jit.movi(lyn.Register.v1, 22)
            jit.movi(lyn.Register.v2, 44)
            jit.addr(lyn.Register.v3, lyn.Register.v1, lyn.Register.v2)
            jit.retr(lyn.Register.v3)
            f = jit.emit_function()
            self.assertEqual(f(), 66)

    def test_execution(self):
        with self.lyn.state() as jit:
            # Create a function that returns 123
            jit.prolog()
            jit.movi(lyn.Register.v0, 123)
            jit.movi(lyn.Register.v1, 456)
            jit.retr(lyn.Register.v0)
            code_ptr = jit.emit()
            self.assertIsNotNone(code_ptr)

            make_func = ctypes.CFUNCTYPE(ctypes.c_int)
            func = make_func(code_ptr)
            result = func()
            self.assertTrue(result is not None)
            self.assertIsInstance(result, int)
            self.assertEqual(result, 123)

    def test_incr(self):
        """Creates a function that increments an integer."""
        with self.lyn.state() as jit:
            jit.prolog()
            num = jit.arg()
            jit.getarg(lyn.Register.r0, num)
            jit.addi(lyn.Register.r0, lyn.Register.r0, 1)
            jit.retr(lyn.Register.r0)
            incr = jit.emit_function(ctypes.c_int, [ctypes.c_int])
            for n in range(100):
                self.assertEqual(incr(n), n+1)

    def test_mul3(self):
        """Creates a function that multiplies integers with three."""
        with self.lyn.state() as jit:
            jit.prolog()
            num = jit.arg()
            jit.getarg(lyn.Register.r0, num)
            jit.muli(lyn.Register.r0, lyn.Register.r0, 3)
            jit.retr(lyn.Register.r0)
            incr = jit.emit_function(ctypes.c_int, [ctypes.c_int])
            for n in range(100):
                self.assertEqual(incr(n), n*3)

    def test_sequential_states(self):
        with self.lyn.state() as a:
            self.assertIsNotNone(a)

        with self.lyn.state() as b:
            self.assertIsNotNone(a)
            self.assertIsNotNone(b)

if __name__ == "__main__":
    unittest.main()
