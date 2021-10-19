from re import fullmatch
import os
import json
from .usuario import User


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
        else:
            user = User(email, password)
            data.append(user.__dict__)
        try:
            with open(myfile, "w", encoding="utf-8", newline="") as file2:
                json.dump(data, file2, indent=2)
        except FileNotFoundError as error:
            raise Excepcion("Wrong file or file path") from error
        except json.JSONDecodeError as error:
            raise Excepcion("Wrong JSON Format") from error
