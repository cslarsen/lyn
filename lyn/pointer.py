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
