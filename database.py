import sqlite3 as sql


class Database:

    def __init__(self):
        pass

    @staticmethod
    def insert_user(data):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"INSERT INTO user VALUES (?,?,?,?,?)"
        cursor.execute(instruction, data)
        table.commit()
        table.close()

    @staticmethod
    def read_content_user(name):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"SELECT * FROM user WHERE name = '" + name + "'"
        cursor.execute(instruction)
        datos = cursor.fetchall()
        table.commit()
        table.close()
        return datos

    @staticmethod
    def read_id_user(name):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"SELECT rowid FROM user WHERE name = '" + name + "'"
        cursor.execute(instruction)
        datos = cursor.fetchone()
        table.commit()
        table.close()
        return datos

    # Esto retorna una lista con un solo elemento

    @staticmethod
    def insert_order(data):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"INSERT INTO orders VALUES (?,?,?,?,?)"
        cursor.execute(instruction, data)
        table.commit()
        table.close()

    @staticmethod
    def read_content_order(data):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"SELECT * FROM orders WHERE restaurant = ? and hour = ?"
        cursor.execute(instruction, data)
        datos = cursor.fetchall()
        table.commit()
        table.close()
        return datos

    @staticmethod
    def insert_key_order(data):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"INSERT INTO keys_order VALUES (?,?)"
        cursor.execute(instruction, data)
        table.commit()
        table.close()

    @staticmethod
    def insert_reserve(data):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"INSERT INTO reserve VALUES (?,?,?,?,?)"
        cursor.execute(instruction, data)
        table.commit()
        table.close()

    @staticmethod
    def read_content_reserve(data):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"SELECT * FROM reserve WHERE restaurant = ? and day = ? and hour = ?"
        cursor.execute(instruction, data)
        datos = cursor.fetchall()
        table.commit()
        table.close()
        return datos

    @staticmethod
    def insert_key_reserve(data):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"INSERT INTO keys_reserve VALUES (?,?)"
        cursor.execute(instruction, data)
        table.commit()
        table.close()

    @staticmethod
    def insert_key(data):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"INSERT INTO keys VALUES (?,?)"
        cursor.execute(instruction, data)
        table.commit()
        table.close()

    @staticmethod
    def find_key(id_user):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"SELECT * FROM keys WHERE rowid = '" + str(id_user) + "'"
        cursor.execute(instruction)
        datos = cursor.fetchone()
        table.commit()
        table.close()
        return datos
    # Esto retorna una lista

    @staticmethod
    def insert_payment(data):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"INSERT INTO payment VALUES (?,?,?,?,?,?)"
        cursor.execute(instruction, data)
        table.commit()
        table.close()

    @staticmethod
    def insert_key_payment(data):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"INSERT INTO keys_payment VALUES (?,?)"
        cursor.execute(instruction, data)
        table.commit()
        table.close()

    # Este devuelve la lista de todos los elementos de la base, podemos hacer uno concreto buscando por nombre

    @staticmethod
    def read_restaurant(tag):
        table = sql.connect("App.db")
        cursor = table.cursor()
        instruction = f"SELECT name FROM restaurants WHERE tag = '" + tag + "' or name = '" + tag + "'"
        cursor.execute(instruction)
        datos = cursor.fetchall()
        table.commit()
        table.close()
        return datos



