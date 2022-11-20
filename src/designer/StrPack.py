class __Autonomy__(object):
    def __init__(self):
        self._buff = ""

    def write(self, out_stream):
        self._buff += out_stream
