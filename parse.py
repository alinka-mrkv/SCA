import idautils
import idc
import db
import hashlib
import ida_nalt
from pathlib import Path
import ppdeep
import tlsh
import pefile
import base64
import os
import lief
from help_module import *


def get_module_info(file_path):
    with open('../log.txt', 'a', encoding='utf-8') as file:
        file.write("INFO - Start parsing module\n")
    # pe = pefile.PE(file_path)
    # module_name = Path(file_path).name
    # module_version = pe.FILE_HEADER.Machine#pe.OPTIONAL_HEADER.MajorImageVersion
    # module_size = pe.OPTIONAL_HEADER.SizeOfImage 
    # module_type = file_path[-3:]
    # module_description = None 
    # module_hash_md5 = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
    # module_hash_sha256 = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
    # module_hash_imphash = pe.get_imphash()
    # module_hash_ssdeep = ppdeep.hash(open(file_path, 'rb').read())
    # module_hash_tlsh = tlsh.hash(open(file_path, 'rb').read())
    # has_symbols = True if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else False
    # try:
    #     export_funcs_count = len([e.name for e in pe.DIRECTORY_ENTRY_EXPORT.symbols])
    # except:
    #     export_funcs_count = 0
    # try:
    #     import_funcs_count = sum(len(d.imports) for d in pe.DIRECTORY_ENTRY_IMPORT)
    # except:
    #     import_funcs_count = 0
    module_name = Path(file_path).name
    binary = lief.parse(module_name).abstract
    module_version = 64 if (binary.header.is_64) else 32
    module_size = os.path.getsize(file_path)
    module_type = module_name.split('.')[-1].lower()
    module_description = None 
    file_data = open(file_path, 'rb').read()
    module_hash_md5 = hashlib.md5(file_data).hexdigest()
    module_hash_sha256 = hashlib.sha256(file_data).hexdigest()
    module_hash_imphash = 0
    module_hash_ssdeep = ppdeep.hash(file_data)
    module_hash_tlsh = tlsh.hash(file_data)
    export_funcs_count = len(binary.exported_functions)
    import_funcs_count = len(binary.imported_functions)
    has_symbols = True if (export_funcs_count != 0 or import_funcs_count != 0) else False
    strings_count = len(list(idautils.Strings(default_setup=False)))
    print(module_name, module_version, module_size, module_type, module_description, 
          module_hash_md5, module_hash_sha256, module_hash_imphash, module_hash_ssdeep, module_hash_tlsh, 
          export_funcs_count, import_funcs_count, has_symbols, strings_count)
    db.execute_postgres_command("INSERT INTO Modules(ModuleName,\
                                ModuleVersion, \
                                ModuleSize, \
                                ModuleType, \
                                ModuleDescription, \
                                ModuleHash_md5, \
                                ModuleHash_sha256, \
                                ModuleHash_imphash,\
                                ModuleHash_ssdeep,\
                                ModuleHash_tlsh, \
                                ModuleSymbols,\
                                ExportFuncsCount,\
                                ImportFuncsCount,\
                                StringsCount) VALUES ('" +
                                str(module_name) + "', " +
                                str(module_version) + ", " +
                                str(module_size) + ", '" +
                                str(module_type) + "', '" +
                                str(module_description) + "', '" +
                                str(module_hash_md5) + "', '" +
                                str(module_hash_sha256) + "', '" +
                                str(module_hash_imphash) + "', '" +
                                str(module_hash_ssdeep) + "', '" +
                                str(module_hash_tlsh) + "', " +
                                str(has_symbols) + ", " +
                                str(export_funcs_count) + ", " +
                                str(import_funcs_count) + ", " +
                                str(strings_count) + ") ON CONFLICT (ModuleHash_sha256) DO NOTHING;")


def get_functions(file_path):
    with open('../log.txt', 'a', encoding='utf-8') as file:
        file.write("INFO - Start parsing functions\n")
    strings_insert = []
    for segment in idautils.Segments():
        for func in idautils.Functions(idc.get_segm_start(segment), idc.get_segm_end(segment)):
            func_end = idc.find_func_end(func)
            function_size = func_end - func
            if(function_size < 10): continue
            function_name = idc.get_func_name(func)
            if(function_name.__contains__("sub_") or len(function_name) > 255): function_name = ""
            func_offset = func - ida_nalt.get_imagebase()
            data = ""
            data = idc.get_bytes(func, int(func_end) - int(func))
            func_hash_md5 = hashlib.md5(data).hexdigest()
            func_hash_sha256 = hashlib.sha256(data).hexdigest()
            func_hash_ssdeep = ppdeep.hash(data)
            func_hash_tlsh = tlsh.hash(data)
            func_code_refs = get_func_refs_count(func, func_end)
            func_args_count = calc_args_count(func)
            func_jmp_count, func_call_count = get_jpm_call_count(func, func_end)
            module_id = db.execute_postgres_command("SELECT ModuleID FROM Modules WHERE ModuleName = '" + Path(file_path).name + "';")
            strings_insert.append("('" +
                    str(function_name) + "', " +
                    str(module_id[0][0]) + ", " +
                    str(func_offset) + ", " +
                    str(function_size) + ", '" +
                    str(func_hash_md5) + "', '" +
                    str(func_hash_sha256) + "', '" +
                    str(func_hash_ssdeep) + "', '" +
                    str(func_hash_tlsh) + "', " +
                    str(func_code_refs) + ", " +
                    str(func_args_count) + ", " +
                    str(func_jmp_count) + ", " +
                    str(func_call_count) + ")")
    db_values = ', '.join([value for value in strings_insert])
    print(db_values)
    db.execute_postgres_command(f"INSERT INTO Functions ( \
                    FuncName,\
                    ModuleID,\
                    FuncOffset,\
                    FunctionSize,\
                    FunctionHash_md5,\
                    FunctionHash_sha256,\
                    FunctionHash_ssdeep, \
                    FunctionHash_tlsh,\
                    FunctionRefs, \
                    FunctionArgsCount, \
                    FunctionJmpCount, \
                    FunctionCallCount \
                    ) VALUES {db_values} ON CONFLICT (FunctionHash_sha256) DO NOTHING;")



def get_strings(file_path):
    with open('../log.txt', 'a', encoding='utf-8') as file:
        file.write("INFO - Start parsing strings\n")
    strings = idautils.Strings(default_setup=False)
    strings = set(strings)
    encoded_strings = []
    for string in strings:
        string = str(string).encode('utf-8')
        string_base64 = base64.b64encode(string).decode('utf-8')
        encoded_strings.append(string_base64)
    values_list = ', '.join([f"('{value}')" for value in encoded_strings])
    db.execute_postgres_command(f"INSERT INTO Strings (Str) VALUES {values_list} ON CONFLICT (Str) DO NOTHING;")



def main():
    file_path = ida_nalt.get_input_file_path() 
    get_module_info(file_path)
    get_functions(file_path)
    get_strings(file_path)
    with open('../log.txt', 'a', encoding='utf-8') as file:
        file.write("INFO - The end of module parsing, you can find your information in DB\n")

if __name__ == "__main__":
    main()