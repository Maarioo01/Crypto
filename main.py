from re import fullmatch
import os
import json
from .usuario import User
from .reserve import Reserve
from .Order import Order


class App:
    def __init__(self):
        pass

    @staticmethod
    def validate_email(email):
        if not isinstance(email, str) or fullmatch(r"^[^@]+@[^@]+\.[a-zA-Z]{2,3}$",email, flags=0) is None:
            return "email not válid"
        return True

    @staticmethod
    def validar_password (password):
        if not isinstance(password, str) or fullmatch("^(?=\w*\d)(?=\w*[A-Z])(?=\w*[a-z])\S{8,16}$",password, flags=0) is None:
            return "password not valid"
        return True

    def Sign_up(self,email, password):
        self.validate_email(email)
        self.validar_password(password)
        myfile = os.path.dirname(os.path.abspath(__file__))+ "poner direccion"
        try:
            with open(myfile, "r", encoding = "utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

        if data:
            for i in data:
                if i["email"] == email:
                    return ("Email ya existe")
                user = User(email, password)
                data.append(user.__dict__)
        user = User(email, password)
        data.append(user.__dict__)
        try:
            with open(myfile, "w", encoding="utf-8", newline="") as file2:
                json.dump(data, file2, indent=2)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

    def log_in(self,email, password):

        self.validate_email(email)
        self.validar_password(password)

        myfile = os.path.dirname(os.path.abspath(__file__)) + "poner direccion"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
        if data:
            for i in data:
                if i["email"] == email:
                    if i["password"] == password:
                        return True
                    return ("Los credenciales no coinciden")
                return ("El email no existe")

    @staticmethod
    def search(self):
        myfile = os.path.dirname(os.path.abspath(__file__)) + "poner direccion"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from err_or
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
        lista_tags = []
        for i in data:
            if i["restaurante"] == "tag":
                return ("tag")
            for j in i["tags"]:
                if j == "tag" :
                    lista_tags.append(j)
        if len(lista_tags) == 0:
            return ("no tenemos coincidencias en nuestra base de datos")

        return lista_tags
    @staticmethod
    def reserve(restaurant, day, hour, email):
        myfile = os.path.dirname(os.path.abspath(__file__)) + "poner direccion"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

        if data:
            for i in data:
                if i["restaurant"] == restaurant and i["day"] == day and i["hour"] == hour and i["email"] == email:
                    return ("This reserve is already done")
            reserve = Reserve(restaurant, day, hour, email)
            data.append(reserve.__dict__)
        reserve = Reserve(restaurant, day, hour, email)
        data.append(reserve.__dict__)
        try:
            with open(myfile, "w", encoding="utf-8", newline="") as file2:
                json.dump(data, file2, indent=2)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error

    @staticmethod
    def order(restaurant, address, email):
        myfile = os.path.dirname(os.path.abspath(__file__)) + "poner direccion"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from err_or
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
        if data:
            for i in data:
                if i["restaurant"] == restaurant and i["address"] == address and i["email"] == email:
                    return ("This order is already done")
                order = Order(restaurant, address, email)
                data.append(order.__dict__)

        order = Order(restaurant, address, email)
        data.append(order.__dict__)
        try:
            with open(myfile, "w", encoding="utf-8", newline="") as file2:
                json.dump(data, file2, indent=2)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error


    def checkout (self, option, credit_card, mail, hour, day, restaurant):
        if option == "tarjeta":
            self.payment_card(credit_card, mail, hour, day, restaurant)
        return "your payment will be made in delivery"

    @staticmethod
    def payment_card(credit_card, mail, hour, day, restaurant):
        myfile = os.path.dirname(os.path.abspath(__file__)) + "poner direccion"
        try:
            with open(myfile, "r", encoding="utf-8", newline="") as file1:
                data = json.load(file1)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from err_or
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
        if data:
            for i in data:

