class GeneratorRegistry:

    def __init__(self):
        self.handlers = []

    def register(self, handler):
        self.handlers.append(handler)

    def get_generator_handler(self, protocol):

        for h in self.handlers:
            if h.match(protocol):
                return h

        return None