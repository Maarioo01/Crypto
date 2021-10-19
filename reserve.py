class Reserve:
    def __init__(self, restaurant, day , hour, email):
        self.__restaurant = restaurant
        self.__day = day
        self.__hour = hour
        self.__email = email

    @property
    def restaurant(self):
        return self.__restaurant

    @restaurant.setter
    def restaurant(self, value):
        self.__restaurant = value

    @property
    def day(self):
        return self.__password

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