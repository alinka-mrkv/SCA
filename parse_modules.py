import idautils
import idc
import idaapi
import ida_nalt
import db
import pefile
import hashlib
from pathlib import Path

def get_module_info(file_path):
    pe = pefile.PE(file_path)
    module_name = Path(file_path).name
    module_version = pe.OPTIONAL_HEADER.MajorImageVersion
    module_size = pe.OPTIONAL_HEADER.SizeOfImage 
    module_type = file_path[-3:]
    module_description = None 
    module_hash_md5 = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
    module_hash_sha256 = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
    module_fuzzyhash = None  # Добавить получение fuzzy-хэша
    has_symbols = True if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else False
    export_funcs_count = len([e.name for e in pe.DIRECTORY_ENTRY_EXPORT.symbols])
    import_funcs_count = sum(len(d.imports) for d in pe.DIRECTORY_ENTRY_IMPORT)
    strings_count = 0  
    db.execute_postgres_command("INSERT INTO Modules(ModuleName,\
                                ModuleVersion, \
                                ModuleSize, \
                                ModuleType, \
                                ModuleDescription, \
                                ModuleHash_md5, \
                                ModuleHash_sha256, \
                                ModuleFuzzyHash, \
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
                                str(module_fuzzyhash) + "', " +
                                str(has_symbols) + ", " +
                                str(export_funcs_count) + ", " +
                                str(import_funcs_count) + ", " +
                                str(strings_count) + ");")
    print(str(module_name) + ", " +
          str(module_version) + ", " +
          str(module_size) + ", " +
          str(module_type) + ", " +
          str(module_description) + ", " +
          str(module_hash_md5) + ", " +
          str(module_hash_sha256) + ", " +
          str(module_fuzzyhash) + ", " +
          str(has_symbols) + ", " +
          str(export_funcs_count) + ", " +
          str(import_funcs_count) + ", " +
          str(strings_count))
    return 

def main():
    file_path = ida_nalt.get_input_file_path() 
    module_info = get_module_info(file_path)
    print(module_info)

if __name__ == "__main__":
    main()