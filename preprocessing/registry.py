class ProtocolRegistry:

    def __init__(self):
        self.handlers = []

    def register(self, handler):
        self.handlers.append(handler)

    def get_handler(self, pkt):

        for h in self.handlers:
            if h.match(pkt):
                return h

        return None