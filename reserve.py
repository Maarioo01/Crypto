class Reserve:
    def __init__(self, restaurant, day, hour, email, nonce):
        self.__restaurant = restaurant
        self.__day = day
        self.__hour = hour
        self.__email = email
        self.__nonce = nonce

    @property
    def restaurant(self):
        return self.__restaurant

    @restaurant.setter
    def restaurant(self, value):
        self.__restaurant = value

    @property
    def day(self):
        return self.__day

    @day.setter
    def day(self, value):
        self.__day = value

    @property
    def hour(self):
        return self.__hour
    @hour.setter
    def hour(self, value):
        self.__hour = value

    @property
    def email(self):
        return self.__email

    @email.setter
    def email(self, value):
        self.__email = value