
class User:
    def __init__(self, name, email, password, nonce):
        self.__name = name
        self.__email = email
        self.__password = password
        self.__nonce = nonce

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, value):
        self.__name = value

    @property
    def email(self):
        return self.__email

    @email.setter
    def email(self, value):
        self.__email = value

    @property
    def password(self):
        return self.__password

    @password.setter
    def password(self, value):
        self.__password = value
