class Order:
    def __init__(self, restaurant, address, email):
        self.__restaurant = restaurant
        self.__address = address
        self.__email = email

    @property
    def restaurant(self):
        return self.__restaurant

    @restaurant.setter
    def restaurant(self, value):
        self.__restaurant = value

    @property
    def address(self):
        return self.__address

    @address.setter
    def address(self, value):
        self.__address = value

    @property
    def email(self):
        return self.__email

    @email.setter
    def email(self, value):
        self.__email = value
