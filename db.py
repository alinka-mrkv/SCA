import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

db_host = os.getenv('DB_HOST')
db_port = os.getenv('DB_PORT')
db_username = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_db = os.getenv('DB_DATABASE')


def init():
    #execute_postgres_command("CREATE DATABASE " + db_db + ";")
    execute_postgres_command("GRANT ALL PRIVILEGES ON DATABASE "+ db_db +" TO " + db_username + ";")
    #execute_postgres_command("\connect " + db_db + ";")

    execute_postgres_command("CREATE TABLE Modules (\
                           ModuleID SERIAL PRIMARY KEY, \
                           ModuleName VARCHAR(50) NOT NULL, \
                           ModuleVersion VARCHAR(50) NOT NULL,\
                           ModuleSize BIGINT,\
                           ModuleType VARCHAR(10) NOT NULL,\
                           ModuleDescription VARCHAR(255) NOT NULL,\
                           ModuleHash_md5 CHAR(128),\
                           ModuleHash_sha256 CHAR(256),\
                           ModuleFuzzyHash CHAR(256),\
                           ModuleSymbols BOOLEAN,\
                           ExportFuncsCount INT,\
                           ImportFuncsCount INT,\
                           StringsCount INT\
                           );")
    execute_postgres_command("CREATE TABLE Functions ( \
                           FunctionID SERIAL PRIMARY KEY, \
                           FuncName VARCHAR(50) NOT NULL,\
                           ModuleID INT,\
                           FuncOffset BIGINT,\
                           FunctionSize BIGINT,\
                           FunctionHash_md5 CHAR(128),\
                           FunctionHash_sha256 CHAR(256),\
                           FunctionFuzzyHash CHAR(256)\
                           );")
    execute_postgres_command("CREATE TABLE Strings (\
                           StringID SERIAL PRIMARY KEY, \
                           Str VARCHAR(256) NOT NULL\
                           );")
    return


def execute_postgres_command(command):
    connection = None
    try:
        connection = psycopg2.connect(user=db_username,
                                    password=db_password,
                                    host=db_host,
                                    port=db_port, 
                                    database=db_db)

        cursor = connection.cursor()
        cursor.execute(command)
        if not "SELECT" in command: connection.commit()
        data = cursor.fetchall()
        return data
    except (Exception, psycopg2.Error) as error:
        print("Error while using PostgreSQL: %s", error)
    finally:
        if connection is not None:
            cursor.close()
            connection.close()