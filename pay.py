class Pay:

    def __init__(self, credit_card, email, address, restaurant, nonce):
        self.__credit_card = credit_card
        self.__email = email
        self.__address = address
        self.__restaurant = restaurant
        self.__nonce = nonce


    @property
    def credit_card(self):
        return self.__credit_card

    @credit_card.setter
    def credit_card(self, value):
        self.__credit_card = value

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
