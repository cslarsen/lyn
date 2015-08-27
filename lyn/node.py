class Node(object):
    """A node in the code (jit_node_t pointer)."""
    def __init__(self, jit_node_ptr):
        self.value = jit_node_ptr

    def __repr__(self):
        return "<Node: jit_node_t at 0x%x>" % self.value
