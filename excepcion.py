class Excepcion(Exception):

    def __init__(self, message):
        self.__message = message
        super().__init__(self.p_message)

    @property
    def p_message(self):
        return self.__message

    @p_message.setter
    def p_message(self, value):
        self.__message = value