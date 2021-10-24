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

    # method to sign up
    def sign_up(self, email, password):
        # first validate email and password
        if not self.validate_email(email) or not self.validate_password(password):
            return
        # open storage of users
        myfile = os.path.dirname(os.path.abspath(__file__)) + "\\almacen_usuarios.json"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

        if data:
            for i in data:
                # first check if the email already exist
                if i['_User__email'] == email:
                    print("Email already exists")
                    return False
        # in case storage is empty or email doesn't exist, generate the encrypt key and store
        nonce = os.urandom(12)
        password_object = Chacha(bytes(password, encoding="utf-8"), key, nonce, bytes(email, encoding="utf-8"))
        password_encrypt = password_object.encrypt(bytes(password, encoding="utf-8"), nonce,
                                                   bytes(email, encoding="utf-8"))
        b64_bytes_password = base64.urlsafe_b64encode(password_encrypt)
        b64_string_password = b64_bytes_password.decode("ascii")
        b64_bytes_nonce = base64.urlsafe_b64encode(nonce)
        b64_string_nonce = b64_bytes_nonce.decode("ascii")
        user = User(email, b64_string_password, b64_string_nonce)
        data.append(user.__dict__)
        # save the updates
        try:
            with open(myfile, "w", encoding="utf-8", newline="") as file2:
                json.dump(data, file2, indent=2)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
        return True

    # method to log in
    def log_in(self, email, password):
        # first validate email and password
        if not self.validate_email(email) or not self.validate_password(password):
            return
        # open storage of users
        myfile = os.path.dirname(os.path.abspath(__file__)) + "\\almacen_usuarios.json"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
        if data:
            for i in data:
                # search the email introduced
                if i['_User__email'] == email:
                    nonce = i['_User__nonce']
                    b64_bytes_nonce_bis = nonce.encode("ascii")
                    bytes_nonce_bis = base64.urlsafe_b64decode(b64_bytes_nonce_bis)
                    password_object = Chacha(bytes(password, encoding="utf-8"), key, bytes_nonce_bis,
                                             bytes(email, encoding="utf-8"))
                    password_encrypt = password_object.encrypt(bytes(password, encoding="utf-8"), bytes_nonce_bis,
                                                               bytes(email, encoding="utf-8"))
                    b64_bytes_password = base64.urlsafe_b64encode(password_encrypt)
                    b64_string_password = b64_bytes_password.decode("ascii")
                    if i['_User__password'] == str(b64_string_password):
                        return True
                    print("credentials don't match")
                    return False
                print("Email doesn't exit")
                return False

    # method to search restaurants/tags
    @staticmethod
    def search(tag):
        # open the storage of restaurants
        myfile = os.path.dirname(os.path.abspath(__file__)) + "\\almacen_restaurants.json"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
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
    @staticmethod
    def reserve(restaurant, day, hour, email):
        # open the storage of reserves
        myfile = os.path.dirname(os.path.abspath(__file__)) + "\\almacen_reservas.json"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

        if data:
            # check if the reserve is already done
            for i in data:
                if i["_Reserve__restaurant"] == restaurant and i["_Reserve__day"] == day and \
                        i["_Reserve__hour"] == hour and i["_Reserve__email"] == email:
                    print("This reserve is already done")
                    return
        reserve = Reserve(restaurant, day, hour, email)
        data.append(reserve.__dict__)
        print("reserve donde")
        # save the updates
        try:
            with open(myfile, "w", encoding="utf-8", newline="") as file2:
                json.dump(data, file2, indent=2)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

    # method to order
    def order(self, restaurant, address, email):
        # open the storage of orders
        myfile = os.path.dirname(os.path.abspath(__file__)) + "\\almacen_orders.json"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
        if data:
            # check if order is already donde
            for i in data:
                if i["_Order__restaurant"] == restaurant and i["_Order__email"] == email:
                    print("This order is already done")
                    return

        nonce = os.urandom(12)
        address_object = Chacha(bytes(address, encoding="utf-8"), key, nonce, bytes(email, encoding="utf-8"))
        address_encrypt = address_object.encrypt(bytes(address, encoding="utf-8"), nonce,
                                                 bytes(email, encoding="utf-8"))
        b64_bytes_address = base64.urlsafe_b64encode(address_encrypt)
        b64_string_address = b64_bytes_address.decode("ascii")
        b64_bytes_nonce = base64.urlsafe_b64encode(nonce)
        b64_string_nonce = b64_bytes_nonce.decode("ascii")
        order = Order(restaurant, b64_string_address, email, b64_string_nonce)
        data.append(order.__dict__)
        print("Order done")
        # save the updates
        try:
            with open(myfile, "w", encoding="utf-8", newline="") as file2:
                json.dump(data, file2, indent=2)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

        option = input("select your payment method")
        self.checkout(option, email, address, restaurant)

    # method to checkout
    def checkout(self, option, email, address, restaurant):
        if option == "tarjeta":
            credit_card = input("Introduce your number card")
            self.payment_card(credit_card, email, address, restaurant)
        return "your payment will be made in delivery"

    # method to pay
    @staticmethod
    def payment_card(credit_card, email, address, restaurant):
        # open the storage of credit-cards
        myfile = os.path.dirname(os.path.abspath(__file__)) + "\\almacen_credit_card.json"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

        nonce = os.urandom(12)
        credit_card_object = Chacha(bytes(credit_card, encoding="utf-8"), key, nonce, bytes(email, encoding="utf-8"))
        credit_card_encrypt = credit_card_object.encrypt(bytes(credit_card, encoding="utf-8"), nonce,
                                                         bytes(email, encoding="utf-8"))
        b64_bytes_credit_card = base64.urlsafe_b64encode(credit_card_encrypt)
        b64_string_credit_card = b64_bytes_credit_card.decode("ascii")
        address_object = Chacha(bytes(address, encoding="utf-8"), key, nonce, bytes(email, encoding="utf-8"))
        address_encrypt = address_object.encrypt(bytes(address, encoding="utf-8"), nonce,
                                                 bytes(email, encoding="utf-8"))
        b64_bytes_address = base64.urlsafe_b64encode(address_encrypt)
        b64_string_address = b64_bytes_address.decode("ascii")
        b64_bytes_nonce = base64.urlsafe_b64encode(nonce)
        b64_string_nonce = b64_bytes_nonce.decode("ascii")

        pay_credit_card = Pay(b64_string_credit_card, email, b64_string_address, restaurant, b64_string_nonce)
        data.append(pay_credit_card.__dict__)
        print("pay already donde")
        try:
            with open(myfile, "w", encoding="utf-8", newline="") as file2:
                json.dump(data, file2, indent=2)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error


def main():
    app = App()
    option = input("sign up or log in?").lower()
    while option != "sign up" and option != "log in":
        option = input("sign up or log in?").lower()
    user = False
    while user is False:
        if option == "sign up":
            email = input("Introduce your email")
            while not app.validate_email(email):
                email = input("Introduce your email")
            password = input("Introduce your password")
            while not app.validate_password(password):
                password = input("Introduce your password")
            user = app.sign_up(email, password)
            if not user:
                print("try again")
        else:
            email = input("Introduce your email")
            while not app.validate_email(email):
                email = input("Introduce your email")
            password = input("Introduce your password")
            while not app.validate_password(password):
                password = input("Introduce your password")
            user = app.log_in(email, password)
            if not user:
                print("try again")

    option = input("search, reserve or order?")
    while option != "exit":
        if option == "search":
            search = input("What you want to search?")
            while not app.search(search):
                search = input("choose a restaurant")
        elif option == "reserve":
            restaurant = input("Introduce the restaurant")
            while not app.search(restaurant):
                restaurant = input("Introduce the restaurant")
            day = input("introduce the day")
            while not app.validate_day(day):
                day = input("introduce the day")
            hour = input("Introduce the hour")
            app.reserve(restaurant, day, hour, email)
        elif option == "order":
            restaurant = input("Introduce the restaurant")
            while not app.search(restaurant):
                restaurant = input("Introduce the restaurant")
            address = input("Introduce the address")
            app.order(restaurant, address, email)

        option = input("search, reserve or order?")

    return


main()
