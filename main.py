from re import fullmatch
import os
import base64
from chacha20 import Chacha
from RSA import RSA
from database import Database
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

key = b"-\x8f%\x93\xf2\xa7\xa6C\xb2{BT\xd9\xdf\x86\x85\xbbl\x10')<\x18\xb2\x87z\xe7\t\x1er]\t"


class App:
    def __init__(self):
        self.database = Database()
        self.rsa = RSA()

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
    def byte_to_str(file):
        # b64_string = file.decode('utf-8').strip
        b64_bytes = base64.urlsafe_b64encode(file)
        b64_string = b64_bytes.decode("ascii")
        return b64_string

    @staticmethod
    def str_to_byte(file):
        # bytes_bis = file.encode('utf-8').strip
        b64_bytes_bis = file.encode("ascii")
        bytes_bis = base64.urlsafe_b64decode(b64_bytes_bis)
        return bytes_bis

    # metodo para guardar las keys en el almacen que le corresponde (para simplificar lineas de codigo)
    def save_key(self, data, nonce, aad, tipo):
        key_object = Chacha(data, key, nonce, aad)
        key_encrypt = key_object.encrypt()
        string_key = self.byte_to_str(key_encrypt)
        string_nonce_key = self.byte_to_str(nonce)
        if tipo == "order":
            self.database.insert_key_order([string_key, string_nonce_key])
        elif tipo == "signup":
            self.database.insert_key([string_key, string_nonce_key])
        elif tipo == "reserve":
            self.database.insert_key_reserve([string_key, string_nonce_key])
        elif tipo == "payment":
            self.database.insert_key_payment([string_key, string_nonce_key])

        return True

    # method to sign up
    def sign_up(self, name, email, password):
        # first validate email and password
        if not self.validate_email(email) or not self.validate_password(password):
            return False
        # open storage of users
        list_data = self.database.read_content_user(name)
        if len(list_data) != 0:
            print("user already exits")
            return False
        # Encrypt password with scrypt
        salt = os.urandom(16)
        kdf = Scrypt(salt, 32, 2 ** 14, 8, 1)
        password_encrypt = kdf.derive(bytes(password, encoding="utf-8"))
        string_password = self.byte_to_str(password_encrypt)
        # encrypt email and salt with Chacha20Poly (el salt no es necesario pero hablado con la profe lo dejamos asi)
        nonce = os.urandom(12)
        key_once = os.urandom(32)
        email_object = Chacha(bytes(email, encoding="utf-8"), key_once, nonce, bytes(name, encoding="utf-8"))
        email_encrypt = email_object.encrypt()
        salt_object = Chacha(salt, key_once, nonce, bytes(name, encoding="utf-8"))
        salt_encrypt = salt_object.encrypt()
        # bytes objects to str to save in db
        string_email = self.byte_to_str(email_encrypt)
        string_nonce = self.byte_to_str(nonce)
        string_salt = self.byte_to_str(salt_encrypt)
        self.database.insert_user([name, string_email, string_password, string_nonce, string_salt])
        # encrypt masterkey with new nonce and save
        nonce_key = os.urandom(12)
        self.save_key(key_once, nonce_key, bytes(name, encoding="utf-8"), "signup")
        return True
        # save the updates

    # method to log in
    def log_in(self, name, password):
        # first validate email and password
        if not self.validate_password(password):
            return False
        # get the user by name from db
        list_data = self.database.read_content_user(name)
        if len(list_data) == 0:
            print("user doesn't exit")
            return False
        # get the rowid to get the key
        id_user = self.database.read_id_user(name)
        # get key to decrypt salt
        list_key = self.database.find_key(id_user[0])
        bytes_key = self.str_to_byte(list_key[0])
        bytes_nonce_key = self.str_to_byte(list_key[1])
        key_object = Chacha(bytes_key, key, bytes_nonce_key, bytes(name, encoding="utf-8"))
        key_once = key_object.decrypt()
        # cogemos el salt correspondiente y lo pasamos a bytes
        bytes_salt = self.str_to_byte(list_data[0][4])
        # cogemos el nonce correspondiente y lo pasamos a bytes
        nonce = self.str_to_byte(list_data[0][3])
        # desencriptamos el salt para hacer scrypt y autenticar
        salt_object = Chacha(bytes_salt, key_once, nonce, bytes(name, encoding="utf-8"))
        salt_decrypt = salt_object.decrypt()
        # encrypt password with the salt to compare
        kdf = Scrypt(salt_decrypt, 32, 2 ** 14, 8, 1)
        password_encrypt = kdf.derive(bytes(password, encoding="utf-8"))
        string_password = self.byte_to_str(password_encrypt)
        if list_data[0][2] != string_password:
            print("Credentials doesn't match")
            return False
        return True

    # method to search restaurants/tags
    def search(self, tag):
        lista_restaurants = self.database.read_restaurant(tag)
        if len(lista_restaurants) == 0:
            print("theres no such a restaurant with this name")
            return False
        if len(lista_restaurants) == 1:
            print(lista_restaurants[0][0])
            return True
        restaurant = ""  # variable para controlar si se ha metido mas de una vez el mismo nombre del restaurante
        contador = 0
        if len(lista_restaurants) > 1:
            for i in lista_restaurants:
                for j in i:
                    if j != restaurant:
                        print(j)
                        restaurant = j
                    else:
                        contador += 1
            if contador >= 1:
                return True
            return False  # False porque es la lista y lo suyo es que eliga un restaurante

    # method to reserve

    def reserve(self, restaurant, day, hour, email):
        # open the storage of reserves
        # buscar restaurant day y hour si lista vacia es que no hay reserva y se puede hacer
        list_restaurant = self.database.read_content_reserve([restaurant, day, hour])
        if len(list_restaurant) != 0:
            print("This reserve is already done")
            return False
        # encrypt email
        nonce = os.urandom(12)
        key_once = os.urandom(32)
        email_object = Chacha(bytes(email, encoding="utf-8"), key_once, nonce, bytes(restaurant, encoding="utf-8"))
        email_encrypt = email_object.encrypt()
        string_email = self.byte_to_str(email_encrypt)
        string_nonce = self.byte_to_str(nonce)
        self.database.insert_reserve([restaurant, day, hour, string_email, string_nonce])
        print("reserve done")
        # save the updates and encrypt key with masterkey
        nonce_key = os.urandom(12)
        self.save_key(key_once, nonce_key, bytes(email, encoding="utf-8"), "reserve")
        # empezamos proceso de firma, concatenamos primero los parametros en un solo str para aplicar Scrypt
        todo_str = restaurant+day+hour+email
        # Cargamos la clave privada que se encuentra en la dirección indicada
        with open("C:\\Users\\Mario\\PycharmProjects\\Crypto\\clave_private.txt", "r") as file:
            private_key = file.read()
        # lo pasamos a bytes, que tendra el formato serializado
        private_key = self.str_to_byte(private_key)
        # deserializamos la clave privada
        private_key = self.rsa.deserialization_private(private_key)
        # realizamos la firma con la clave privada
        signature = self.rsa.sign_document(bytes(todo_str, encoding="utf-8"), private_key)
        # pasamos a str la firma y los datos encriptados para guardarlos en la base de datos
        signature_str = self.byte_to_str(signature)
        self.database.insert_sign_reserve([todo_str, signature_str])

        return True

    # metodo para simular la verificación que un usuario quiere hacer
    def reserve_verify(self, restaurant, day, hour, email):
        # Cargamos la clave publica que se encuentra en la direccion indicada
        with open("C:\\Users\\Mario\\PycharmProjects\\Crypto\\clave_publica.txt", "r") as file:
            public_key = file.read()
        # lo pasamos a bytes, que tendra el formato serializado
        public_key = self.str_to_byte(public_key)
        # deserializamos la clave publica
        public_key = self.rsa.deserialization_public(public_key)
        # concatenamos los parametros
        reserve = restaurant+day+hour+email
        # obtenemos de la base de datos la firma que corresponda con esos parámetros, si esta vacío no existe
        signature = self.database.search_signature([reserve])
        if len(signature) == 0:
            print("This reserve doesn't exit")
            return
        signature = self.str_to_byte(signature[0][0])
        # realizamos la comprobación de la firma, para saber si está bien
        self.rsa.verify_document(bytes(reserve, encoding="utf-8"), signature, public_key)
        print("All correct")
        return True

    # method to order
    def order(self, restaurant, address, email, hour):
        # open the storage of orders
        # Con esta opción solo esta disponible hacer un pedido por cada hora es decir a las 2 no se pueden tener
        # dos pedidos
        list_order = self.database.read_content_order([restaurant, hour])
        if len(list_order) != 0:
            print("We can't offer you this service")
            return False
        # encrypt email and address
        nonce = os.urandom(12)
        key_once = os.urandom(32)
        address_object = Chacha(bytes(address, encoding="utf-8"), key_once, nonce, bytes(restaurant, encoding="utf-8"))
        address_encrypt = address_object.encrypt()
        string_address = self.byte_to_str(address_encrypt)
        email_object = Chacha(bytes(email, encoding="utf-8"), key_once, nonce, bytes(restaurant, encoding="utf-8"))
        email_encrypt = email_object.encrypt()
        string_email = self.byte_to_str(email_encrypt)
        string_nonce = self.byte_to_str(nonce)
        self.database.insert_order([restaurant, hour, string_address, string_email, string_nonce])
        print("Order done")
        # save and encrypt key with masterkey
        nonce_key = os.urandom(12)
        self.save_key(key_once, nonce_key, bytes(email, encoding="utf-8"), "order")
        # empieza la parte para realizar el payment
        option = input("select your payment method, cash or card: ")
        while option != "cash" and option != "card":
            option = input("select your payment method: ").lower()
        self.checkout(option, email, "order", restaurant)

    # method to checkout
    def checkout(self, option, email, type, restaurant):
        if option == "card":
            credit_card = input("Introduce your number card: ")
            self.payment(credit_card, email, type, restaurant, option)
        print("your payment will be made in delivery")
        self.payment("None", email, type, restaurant, option)

    # method to pay
    def payment(self, credit_card, email, type, restaurant, option):
        # open the storage of credit-cards
        # encrypt number of credit card and email
        nonce = os.urandom(12)
        key_once = os.urandom(32)
        string_credit_card = credit_card
        if credit_card != "None":
            credit_card_object = Chacha(bytes(credit_card, encoding="utf-8"), key_once, nonce,
                                        bytes(restaurant, encoding="utf-8"))
            credit_card_encrypt = credit_card_object.encrypt()
            string_credit_card = self.byte_to_str(credit_card_encrypt)
        email_object = Chacha(bytes(email, encoding="utf-8"), key_once, nonce, bytes(restaurant, encoding="utf-8"))
        email_encrypt = email_object.encrypt()
        string_email = self.byte_to_str(email_encrypt)
        string_nonce = self.byte_to_str(nonce)
        self.database.insert_payment([string_credit_card, string_email, type, restaurant, string_nonce, option])
        print("pay already saved")
        # save and encrypt key with masterkey
        nonce_key = os.urandom(12)
        self.save_key(key_once, nonce_key, bytes(email, encoding="utf-8"), "payment")
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

    option = input("search, reserve, order, verify or exit?: ")
    while option != "exit":
        if option == "search":
            search = input("What you want to search?: ").lower()
            while not app.search(search):
                search = input("choose a restaurant: ").lower()
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
            address = input("Introduce the address: ").lower()
            hour = input("Introduce the hour: ")
            app.order(restaurant, address, email, hour)
        elif option == "verify":
            restaurant = input("Introduce the restaurant: ")
            while not app.search(restaurant):
                restaurant = input("Introduce the restaurant: ")
            day = input("introduce the day: ")
            while not app.validate_day(day):
                day = input("introduce the day: ")
            hour = input("Introduce the hour: ")
            app.reserve_verify(restaurant, day, hour, email)

        option = input("search, reserve, order, verify or exit?: ")

    return


# esta parte muestra como se han creado y guardado la clave privada y publica de rsa para firmar
def rsa_main():
    app = App()
    # generamos la clave privada
    private_key = app.rsa.generate_private_key()
    # generamos la clave publica
    public_key = app.rsa.generate_public_key(private_key)
    # serializamos la clave privada para pasarlo a str y guardarlo en el txt
    private_key_serialize = app.rsa.serialization_private(private_key)
    # serializamos la clave privada para pasarlo a str y guardarlo en el txt
    public_key_serialize = app.rsa.serialization_public(public_key)
    # pasamos las dos claves de bytes a str
    private_key_str = app.byte_to_str(private_key_serialize)
    public_key_str = app.byte_to_str(public_key_serialize)
    # Con esta parte generamos los archivos donde se guardar y lo escribimos
    with open("C:\\Users\\Mario\\PycharmProjects\\Crypto\\clave_private.txt", "w") as file:
        file.write(private_key_str)
    with open("C:\\Users\\Mario\\PycharmProjects\\Crypto\\clave_publica.txt", "w") as file2:
        file2.write(public_key_str)


main()


"""Cambiar metodo de payment, ahora en reserve no se llama porque no se puede pagar una reserva por la app, solo se llama
desde order, y para poder conseguir facilmente los id etc, se guardan todos en el mismo fichero, si el tipo es order
credit number se pone a none. ADEMÁS HACER METODO PARA GUARDAR LA MASTER KEY(que vaya desde que se genera el nonce de la
key hasta que se accede a la base, hacer metodo que se llame savekey y hace todo eso? añadir tambien regex de 
direeciones?"""

"""Hacer hash a los datos concatenados con Scrypt para hacer la función resumen y firmar, hacer en order y en 
creditcard. HACER UNA CLASE APARTE QUE TENGA LOS METODOS DE LEER, SERIALIZAR Y DESERIALIZAR, FIRMAR Y VERIFICAR"""
