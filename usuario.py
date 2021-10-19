
class User:
    def __init__(self, email, password):
        self.__email = email
        self.__password = password

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
    def password(self,value):
        self.__password = value