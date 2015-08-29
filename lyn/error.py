class LynError(Exception):
    def __init__(self, *args, **kw):
        super(LynError, self).__init__(*args, **kw)
