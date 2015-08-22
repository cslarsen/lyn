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
            jit.movi(lyn.Register.V0, 123)
            code_ptr = jit.emit()
            self.assertIsNotNone(code_ptr)

    def test_execution(self):
        with self.lyn.state() as jit:
            # Create a function that returns 123
            jit.prolog()
            jit.movi(lyn.Register.V0, 123)
            jit.movi(lyn.Register.V1, 456)
            jit.retr(lyn.Register.V0)
            code_ptr = jit.emit()
            self.assertIsNotNone(code_ptr)

            make_func = ctypes.CFUNCTYPE(ctypes.c_int)
            func = make_func(code_ptr)
            result = func()
            self.assertTrue(result is not None)
            self.assertIsInstance(result, int)
            self.assertEqual(result, 123)

    def test_sequential_states(self):
        with self.lyn.state() as a:
            self.assertIsNotNone(a)

        with self.lyn.state() as b:
            self.assertIsNotNone(a)

if __name__ == "__main__":
    unittest.main()
