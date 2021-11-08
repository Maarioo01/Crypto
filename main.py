from re import fullmatch
import os
import json
import base64
from chacha20 import Chacha
from usuario import User
from reserve import Reserve
from Order import Order
from pay import Pay
from excepcion import Excepcion

key = bytes("\xc7x\x01z\xaen\xa0i\xb8G\xa9\xc4!\xc7\xc2\x08!BX9\x8eA\0", encoding="utf-8")


class App:
    def __init__(self):
        pass

    # method to validate email
    @staticmethod
    def validate_email(email):
        if not isinstance(email, str) or fullmatch(r"^[^@]+@[^@]+\.[a-zA-Z]{2,3}$", email, flags=0) is None:
            print("email not valid")
            return False
        return True

    # method to validate password
    @staticmethod
    def validate_password(password):
        if not isinstance(password, str) or fullmatch(r"^(?=\w*\d)(?=\w*[A-Z])(?=\w*[a-z])\S{8,16}$", password,
                                                      flags=0) is None:
            print("password must contain Upper and lower characters, digits and special characters")
            return False
        return True

    # method to validate days
    @staticmethod
    def validate_day(day):
        if not isinstance(day, str) or (int(day) < 1) or (int(day) > 30):
            print("day not valid")
            return False
        return True

    @staticmethod
    def open_json(url):
        myfile = os.path.dirname(os.path.abspath(__file__)) + url
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
        return data

    @staticmethod
    def write_json(url, data):
        myfile = os.path.dirname(os.path.abspath(__file__)) + url
        try:
            with open(myfile, "w", encoding="utf-8", newline="") as file2:
                json.dump(data, file2, indent=2)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

    @staticmethod
    def byte_to_str(file):
        b64_bytes = base64.urlsafe_b64encode(file)
        b64_string = b64_bytes.decode("ascii")
        return b64_string

    @staticmethod
    def str_to_byte(file):
        b64_bytes_bis = file.encode("ascii")
        bytes_bis = base64.urlsafe_b64decode(b64_bytes_bis)
        return bytes_bis

    # method to sign up
    def sign_up(self, name, email, password):
        # first validate email and password
        if not self.validate_email(email) or not self.validate_password(password):
            return
        # open storage of users
        data = self.open_json("\\almacen_usuarios.json")
        if data:
            for i in data:
                # first check if the email already exist
                if i['_User__name'] == name:
                    print("User already exists")
                    return False
        # in case storage is empty or email doesn't exist, generate the encrypt key and store
        nonce = os.urandom(12)
        password_object = Chacha(bytes(password, encoding="utf-8"), key, nonce, bytes(name, encoding="utf-8"))
        password_encrypt = password_object.encrypt()
        string_password = self.byte_to_str(password_encrypt)
        email_object = Chacha(bytes(email, encoding="utf-8"), key, nonce, bytes(name, encoding="utf-8"))
        email_encrypt = email_object.encrypt()
        string_email = self.byte_to_str(email_encrypt)
        string_nonce = self.byte_to_str(nonce)
        user = User(name, string_email, string_password, string_nonce)
        data.append(user.__dict__)
        self.write_json("\\almacen_usuarios.json", data)
        return True
        # save the updates

    # method to log in
    def log_in(self, name, password):
        # first validate email and password
        if not self.validate_password(password):
            return
        # open storage of users
        data = self.open_json("\\almacen_usuarios.json")
        if data:
            for i in data:
                # search the email introduced
                if i['_User__name'] == name:
                    nonce = i['_User__nonce']
                    bytes_nonce = self.str_to_byte(nonce)
                    password_object = Chacha(bytes(password, encoding="utf-8"), key, bytes_nonce,
                                             bytes(name, encoding="utf-8"))
                    password_encrypt = password_object.encrypt()
                    string_password = self.byte_to_str(password_encrypt)
                    if i['_User__password'] == string_password:
                        return True
                    print("credentials don't match")
                    return False
                print("Name doesn't exit")
                return False
        print("Name doesn't exit")
        return False

    # method to search restaurants/tags
    def search(self, tag):
        # open the storage of restaurants
        data = self.open_json("\\almacen_restaurants.json")
        # create a list to save the tags
        list_tags = []
        for i in data:
            if i["restaurant"] == tag:
                print(tag)
                return True
            for j in i["tags"]:
                if j == tag:
                    list_tags.append(i["restaurant"])
        if len(list_tags) == 0:
            print("sorry, we don't have this service, try again please")
            return False
        print(list_tags)
        return False

    # method to reserve
    def reserve(self, restaurant, day, hour, email):
        # open the storage of reserves
        data = self.open_json("\\almacen_reservas.json")
        if data:
            # check if the reserve is already done
            for i in data:
                if i["_Reserve__restaurant"] == restaurant and i["_Reserve__day"] == day and \
                        i["_Reserve__hour"] == hour:
                    nonce = i['_Reserve__nonce']
                    bytes_nonce = self.str_to_byte(nonce)
                    email_object = Chacha(bytes(email, encoding="utf-8"), key, bytes_nonce,
                                          bytes(restaurant, encoding="utf-8"))
                    email_encrypt = email_object.encrypt()
                    string_email = self.byte_to_str(email_encrypt)
                    if i["_Reserve__email"] == string_email:
                        print("This reserve is already done")
                        return
        nonce = os.urandom(12)
        email_object = Chacha(bytes(email, encoding="utf-8"), key, nonce, bytes(restaurant, encoding="utf-8"))
        email_encrypt = email_object.encrypt()
        string_email = self.byte_to_str(email_encrypt)
        string_nonce = self.byte_to_str(nonce)
        reserve = Reserve(restaurant, day, hour, string_email, string_nonce)
        data.append(reserve.__dict__)
        print("reserve donde")
        # save the updates
        self.write_json("\\almacen_reservas.json", data)
        option = input("select your payment method, cash or card: ")
        self.checkout(option, email, "reserve", restaurant)

    # method to order
    def order(self, restaurant, address, email):
        # open the storage of orders
        data = self.open_json("\\almacen_orders.json")
        if data:
            # check if order is already donde
            for i in data:
                if i["_Order__restaurant"] == restaurant:
                    nonce = i['_Reserve__nonce']
                    bytes_nonce = self.str_to_byte(nonce)
                    email_object = Chacha(bytes(email, encoding="utf-8"), key, bytes_nonce,
                                          bytes(restaurant, encoding="utf-8"))
                    email_encrypt = email_object.encrypt()
                    string_email = self.str_to_byte(email_encrypt)
                    if i["_Order__email"] == string_email:
                        print("This order is already done")
                        return

        nonce = os.urandom(12)
        address_object = Chacha(bytes(address, encoding="utf-8"), key, nonce, bytes(restaurant, encoding="utf-8"))
        address_encrypt = address_object.encrypt()
        string_address = self.byte_to_str(address_encrypt)
        email_object = Chacha(bytes(email, encoding="utf-8"), key, nonce, bytes(restaurant, encoding="utf-8"))
        email_encrypt = email_object.encrypt()
        string_email = self.byte_to_str(email_encrypt)
        string_nonce = self.byte_to_str(nonce)
        order = Order(restaurant, string_address, string_email, string_nonce)
        data.append(order.__dict__)
        print("Order done")
        # save the updates
        self.write_json("\\almacen_orders.json", data)
        option = input("select your payment method, cash or card: ")
        while option != "cash" and option != "card":
            option = input("select your payment method: ").lower()
        self.checkout(option, email, "order", restaurant)

    # method to checkout
    def checkout(self, option, email, type, restaurant):
        if option == "card":
            credit_card = input("Introduce your number card: ")
            self.payment_card(credit_card, email, type, restaurant)
        return print("your payment will be made in delivery")

    # method to pay
    def payment_card(self, credit_card, email, type, restaurant):
        # open the storage of credit-cards
        data = self.open_json("\\almacen_credit_card.json")

        nonce = os.urandom(12)
        credit_card_object = Chacha(bytes(credit_card, encoding="utf-8"), key, nonce,
                                    bytes(restaurant, encoding="utf-8"))
        credit_card_encrypt = credit_card_object.encrypt()
        string_credit_card = self.byte_to_str(credit_card_encrypt)
        email_object = Chacha(bytes(email, encoding="utf-8"), key, nonce, bytes(restaurant, encoding="utf-8"))
        email_encrypt = email_object.encrypt()
        string_email = self.byte_to_str(email_encrypt)
        string_nonce = self.byte_to_str(nonce)
        pay_credit_card = Pay(string_credit_card, string_email, type, restaurant, string_nonce)
        data.append(pay_credit_card.__dict__)
        print("pay already done")
        self.write_json("\\almacen_credit_card.json", data)
        return True


def main():
    app = App()
    option = input("sign up or log in?: ").lower()
    while option != "sign up" and option != "log in":
        option = input("sign up or log in?: ").lower()
    user = False
    while user is False:
        if option == "sign up":
            name = input("Introduce your name: ")
            email = input("Introduce your email: ")
            while not app.validate_email(email):
                email = input("Introduce your email: ")
            password = input("Introduce your password: ")
            while not app.validate_password(password):
                password = input("Introduce your password: ")
            user = app.sign_up(name, email, password)
            if not user:
                print("try again")
        else:
            name = input("Introduce your name: ")
            email = input("Introduce your email: ")
            while not app.validate_email(email):
                email = input("Introduce your email: ")
            password = input("Introduce your password: ")
            while not app.validate_password(password):
                password = input("Introduce your password: ")
            user = app.log_in(name, password)
            if not user:
                option = input("sign up or log in?: ").lower()
                while option != "sign up" and option != "log in":
                    option = input("sign up or log in?: ").lower()

    option = input("search, reserve or order?: ")
    while option != "exit":
        if option == "search":
            search = input("What you want to search?: ")
            while not app.search(search):
                search = input("choose a restaurant: ")
        elif option == "reserve":
            restaurant = input("Introduce the restaurant: ")
            while not app.search(restaurant):
                restaurant = input("Introduce the restaurant: ")
            day = input("introduce the day: ")
            while not app.validate_day(day):
                day = input("introduce the day: ")
            hour = input("Introduce the hour: ")
            app.reserve(restaurant, day, hour, email)
        elif option == "order":
            restaurant = input("Introduce the restaurant: ")
            while not app.search(restaurant):
                restaurant = input("Introduce the restaurant: ")
            address = input("Introduce the address: ")
            app.order(restaurant, address, email)

        option = input("search, reserve or order?: ")

    return

# hacer metodo con doble key


main()
