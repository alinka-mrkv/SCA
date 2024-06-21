import psycopg2
import os
from dotenv import load_dotenv
import logging


logging.basicConfig(
    handlers=[logging.FileHandler(filename='log.txt', encoding='utf-8')], format='%(levelname)s - %(message)s', level=logging.INFO
)

logger = logging.getLogger('logger')

load_dotenv()

db_host = os.getenv('DB_HOST')
db_port = os.getenv('DB_PORT')
db_username = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_db = os.getenv('DB_DATABASE')


def init():
    logger.info("Database initialization")
    execute_postgres_command("CREATE EXTENSION IF NOT EXISTS pg_similarity;")
    execute_postgres_command("CREATE TABLE Modules (\
                           ModuleID SERIAL PRIMARY KEY, \
                           ModuleName VARCHAR(256) NOT NULL, \
                           ModuleVersion VARCHAR(256) NOT NULL,\
                           ModuleSize BIGINT,\
                           ModuleType VARCHAR(10) NOT NULL,\
                           ModuleDescription VARCHAR(256) NOT NULL,\
                           ModuleHash_md5 VARCHAR(256) NOT NULL,\
                           ModuleHash_sha256 VARCHAR(256) NOT NULL,\
                           ModuleHash_imphash VARCHAR(256) NOT NULL,\
                           ModuleHash_ssdeep VARCHAR(256) NOT NULL,\
                           ModuleHash_tlsh VARCHAR(256) NOT NULL, \
                           ModuleSymbols BOOLEAN,\
                           ExportFuncsCount INT,\
                           ImportFuncsCount INT,\
                           StringsCount INT,\
                           CONSTRAINT UQ_ModuleHash_md5 UNIQUE (ModuleHash_md5),\
                           CONSTRAINT UQ_ModuleHash_sha256 UNIQUE (ModuleHash_sha256)\
                           );")
    execute_postgres_command("CREATE TABLE Functions ( \
                           FunctionID SERIAL PRIMARY KEY, \
                           FuncName VARCHAR(256) NOT NULL,\
                           ModuleID INT,\
                           FuncOffset BIGINT,\
                           FunctionSize BIGINT,\
                           FunctionHash_md5 VARCHAR(256) NOT NULL,\
                           FunctionHash_sha256 VARCHAR(256) NOT NULL,\
                           FunctionHash_ssdeep VARCHAR(256) NOT NULL, \
                           FunctionHash_tlsh VARCHAR(256) NOT NULL,\
                           FunctionRefs INT, \
                           FunctionArgsCount INT, \
                           FunctionJmpCount INT, \
                           FunctionCallCount INT, \
                           CONSTRAINT UQ_FunctionHash_md5 UNIQUE (FunctionHash_md5),\
                           CONSTRAINT UQ_FunctionHash_sha256 UNIQUE (FunctionHash_sha256)\
                           );")
    execute_postgres_command("CREATE TABLE Strings (\
                           StringID SERIAL PRIMARY KEY, \
                           Str BYTEA NOT NULL,\
                           CONSTRAINT UQ_Str UNIQUE (Str) \
                           );")
    
    execute_postgres_command("CREATE INDEX IF NOT EXISTS idx_modules_module_id ON Modules(ModuleID);")
    execute_postgres_command("CREATE INDEX IF NOT EXISTS idx_functions_ssdeep ON Functions(FunctionHash_ssdeep);")
    execute_postgres_command("CREATE INDEX IF NOT EXISTS idx_functions_tlsh ON Functions(FunctionHash_tlsh);")
    execute_postgres_command("CREATE INDEX IF NOT EXISTS idx_functions_refs ON Functions(FunctionRefs);")
    execute_postgres_command("CREATE INDEX IF NOT EXISTS idx_functions_args ON Functions(FunctionArgsCount);")
    execute_postgres_command("CREATE INDEX IF NOT EXISTS idx_functions_call ON Functions(FunctionCallCount);")
    execute_postgres_command("CREATE INDEX IF NOT EXISTS idx_functions_jmp ON Functions(FunctionJmpCount);")
    execute_postgres_command("CREATE INDEX IF NOT EXISTS idx_strings_str ON Strings(Str);")
    logger.info("The end of DB initialization")
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
        if error is not "no results to fetch": logger.info(error)
    finally:
        if connection is not None:
            cursor.close()
            connection.close()