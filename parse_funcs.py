import idautils
import idc
import idaapi
import db
import hashlib
import ida_nalt
from pathlib import Path
import re

file_path = ida_nalt.get_input_file_path() 

for segment in idautils.Segments():
    for func in idautils.Functions(idc.get_segm_start(segment), idc.get_segm_end(segment)):
        function_name = idc.get_func_name(func)
        if(function_name.__contains__("sub_")): function_name = ""
        func_offset = func - ida_nalt.get_imagebase()
        function_size = idc.find_func_end(func) - func
        data = ""
        with open(file_path, 'rb') as f:
            f.seek(func)
            data = f.read(idc.find_func_end(func) - func)
        func_hash_md5 = hashlib.md5(data).hexdigest()
        func_hash_sha256 = hashlib.sha256(data).hexdigest()
        func_fuzzyhash = None  # Добавить получение fuzzy-хэша
        reg = re.compile(r'\d')
        module_id = db.execute_postgres_command("SELECT ModuleID FROM Modules WHERE ModuleName = '" + Path(file_path).name + "';")
        db.execute_postgres_command("INSERT INTO Functions ( \
                           FuncName,\
                           ModuleID,\
                           FuncOffset,\
                           FunctionSize,\
                           FunctionHash_md5,\
                           FunctionHash_sha256,\
                           FunctionFuzzyHash\
                           ) VALUES ('" +
                           str(function_name) + "', " +
                           str(module_id[0][0]) + ", " +
                           str(func_offset) + ", " +
                           str(function_size) + ", '" +
                           str(func_hash_md5) + "', '" +
                           str(func_hash_sha256) + "', '" +
                           str(func_fuzzyhash) + 
                           "');")
        
        print(str(function_name) + ", " +
            str(module_id) + ", " +
            str(func_offset) + ", " +
            str(function_size) + ", " +
            str(func_hash_md5) + ", " +
            str(func_hash_sha256) + ", " +
            str(func_fuzzyhash))