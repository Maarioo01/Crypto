from re import fullmatch
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from chacha20 import Chacha
from usuario import User
from reserve import Reserve
from Order import Order
from pay import Pay
from excepcion import Excepcion
key = bytes("\xc7x\x01z\xaen\xa0i\xb8G\xa9\xc4!\xc7\xc2\x08!BX9\x8eA\0", encoding ="utf-8")


class App:
    def __init__(self):
        pass

    @staticmethod
    def validate_email(email):
        if not isinstance(email, str) or fullmatch(r"^[^@]+@[^@]+\.[a-zA-Z]{2,3}$",email, flags=0) is None:
            print("email not valid")
            return False
        return True

    @staticmethod
    def validate_password(password):
        if not isinstance(password, str) or fullmatch(r"^(?=\w*\d)(?=\w*[A-Z])(?=\w*[a-z])\S{8,16}$",password, flags=0) is None:
            print("password not valid")
            return False
        return True

    @staticmethod
    def validate_day(day):
        if not isinstance(day, str) or (int(day) < 1) or (int(day) > 30):
            print("day not valid")
            return False
        return True

    def Sign_up(self, email, password):
        if not self.validate_email(email) or not self.validate_password(password):
            return
        myfile = os.path.dirname(os.path.abspath(__file__)) + "\\almacen_usuarios.json"
        try:
            with open(myfile, "r", encoding = "utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
        nonce = os.urandom(12)
        a = Chacha(bytes(password, encoding ="utf-8"), key, nonce, bytes(email, encoding ="utf-8"))
        b = a.encrypt(bytes(password, encoding ="utf-8"), nonce, bytes(email, encoding ="utf-8"))
        if data:
            for i in data:
                if i['_User__email'] == email:
                    print("Email ya existe")
                    return False
            user = User(email, str(b))
            data.append(user.__dict__)
        else:
            user = User(email, str(b))
            data.append(user.__dict__)
        try:
            with open(myfile, "w", encoding="utf-8", newline="") as file2:
                json.dump(data, file2, indent=2)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
        return True

    def log_in(self, email, password):
        if not self.validate_email(email) or not self.validate_password(password):
            return
        myfile = os.path.dirname(os.path.abspath(__file__)) + "\\almacen_usuarios.json"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
        nonce = os.urandom(12)
        a = Chacha(bytes(password, encoding="utf-8"), key, nonce, bytes(email, encoding="utf-8"))
        b = a.encrypt(bytes(password, encoding="utf-8"), nonce, bytes(email, encoding="utf-8"))
        print(b)
        if data:
            for i in data:
                if i['_User__email'] == email:
                    if i['_User__password'] == str(b):
                        return True
                    print ("Los credenciales no coinciden")
                    return False
                print ("El email no existe")
                return False

    @staticmethod
    def search(tag):
        myfile = os.path.dirname(os.path.abspath(__file__)) + "\\almacen_restaurants.json"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
        lista_tags = []
        for i in data:
            if i["restaurant"] == tag:
                print(tag)
                return True
            for j in i["tags"]:
                if j == tag:
                    lista_tags.append(j)
        if len(lista_tags) == 0:
            print("no tenemos coincidencias en nuestra base de datos, vuelva a buscar")
            return False

        return lista_tags

    @staticmethod
    def reserve(restaurant, day, hour, email):

        myfile = os.path.dirname(os.path.abspath(__file__)) + "\\almacen_reservas.json"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

        if data:
            for i in data:
                if i["_Reserve__restaurant"] == restaurant and i["_Reserve__day"] == day and i["_Reserve__hour"] == hour \
                        and i["_Reserve__email"] == email:
                    print("This reserve is already done")
                    return
            reserve = Reserve(restaurant, day, hour, email)
            data.append(reserve.__dict__)
        else:
            reserve = Reserve(restaurant, day, hour, email)
            data.append(reserve.__dict__)
        try:
            with open(myfile, "w", encoding="utf-8", newline="") as file2:
                json.dump(data, file2, indent=2)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

    def order(self, restaurant, address, email):
        myfile = os.path.dirname(os.path.abspath(__file__)) + "\\almacen_orders.json"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
        if data:
            for i in data:
                if i["_Order__restaurant"] == restaurant and i["_Order__address"] == address and i["_Order__email"] == email:
                    print ("This order is already done")
                    return
                order = Order(restaurant, address, email)
                data.append(order.__dict__)
        else:
            order = Order(restaurant, address, email)
            data.append(order.__dict__)

        try:
            with open(myfile, "w", encoding="utf-8", newline="") as file2:
                json.dump(data, file2, indent=2)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

        option = input("select your payment method")
        self.checkout(option, email, address, restaurant)

    def checkout (self, option, email,address, restaurant):
        if option == "tarjeta":
            credit_card = input("Introduce your number card")
            self.payment_card(credit_card, email, address, restaurant)
        return "your payment will be made in delivery"

    @staticmethod
    def payment_card(credit_card, email, address, restaurant):
        myfile = os.path.dirname(os.path.abspath(__file__)) + "\\almacen_credit_card.json"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

        pay_credit_card = Pay(credit_card, email, address, restaurant)
        data.append(pay_credit_card.__dict__)

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
            user = app.Sign_up(email, password)
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
            app.search(search)
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
