import idautils
import idc
import hashlib
import ida_nalt
import pandas as pd
import tlsh
import ppdeep
import pefile
from pathlib import Path
from help_module import *
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE



def get_module_info(file_path):
    columns = ['ModuleName', 'ModuleVersion',
               'ModuleSize', 'ModuleType', 
               'ModuleDescription', 'ModuleHash_md5', 
               'ModuleHash_sha256', 'ModuleHash_imphash',
               'ModuleHash_ssdeep', 'ModuleHash_tlsh',
               'ModuleSymbols', 'ExportFuncsCount',
               'ImportFuncsCount', 'StringsCount']
    new_row = []
    pe = pefile.PE(file_path)
    module_name = Path(file_path).name
    module_version = pe.FILE_HEADER.Machine#pe.OPTIONAL_HEADER.MajorImageVersion
    module_size = pe.OPTIONAL_HEADER.SizeOfImage 
    module_type = file_path[-3:]
    module_description = None 
    module_hash_md5 = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
    module_hash_sha256 = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
    module_hash_imphash = pe.get_imphash()
    module_hash_ssdeep = ppdeep.hash(open(file_path, 'rb').read())
    module_hash_tlsh = tlsh.hash(open(file_path, 'rb').read())
    has_symbols = True if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else False
    try:
        export_funcs_count = len([e.name for e in pe.DIRECTORY_ENTRY_EXPORT.symbols])
    except:
        export_funcs_count = 0
    try:
        import_funcs_count = sum(len(d.imports) for d in pe.DIRECTORY_ENTRY_IMPORT)
    except:
        import_funcs_count = 0
    strings_count = len(list(idautils.Strings()))
    new_row.append(pd.Series([module_name, module_version, 
                              module_size, module_type, 
                              module_description, module_hash_md5, 
                              module_hash_sha256, module_hash_imphash, 
                              module_hash_ssdeep, module_hash_tlsh, 
                              has_symbols, export_funcs_count, 
                              import_funcs_count, strings_count], index=columns))
    df = pd.DataFrame(new_row, columns=columns)
    return df


def get_funcs(file_path):
    columns = ['FuncName', 'ModuleID', 
           'FuncOffset', 'FunctionSize', 
           'FunctionHash_md5', 'FunctionHash_sha256', 
           'FunctionHash_ssdeep', 'FunctionHash_tlsh', 
           'FunctionRefs', 'FunctionArgsCount', 
           'FunctionJmpCount', 'FunctionCallCount', 'Confidence']
    new_row = []

    for segment in idautils.Segments():
        for func in idautils.Functions(idc.get_segm_start(segment), idc.get_segm_end(segment)):
            func_end = idc.find_func_end(func)
            function_size = func_end - func
            if(function_size < 10): continue
            function_name = idc.get_func_name(func)
            if(function_name.__contains__("sub_")): function_name = ""
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
            confidence = 0
            if(function_name != ""): new_row.append(pd.Series([function_name, 0, func_offset, function_size, func_hash_md5, func_hash_sha256, func_hash_ssdeep, func_hash_tlsh, func_code_refs, func_args_count, func_jmp_count, func_call_count, confidence], index=columns))

    df = pd.DataFrame(new_row, columns=columns)
    return df


def get_strings(file_path):
    columns = ['Str']
    new_row = []
    strings = []
    strings = idautils.Strings(default_setup=False)
    strings = set(strings)
    for string in strings:
        new_row.append(pd.Series([string], index=columns))
    df = pd.DataFrame(new_row, columns=columns)
    return df


def main():
    file_path = ida_nalt.get_input_file_path() 
    df_module = get_module_info(file_path)
    df_funcs = get_funcs(file_path)
    df_strings = get_strings(file_path)
    df_strings = df_strings.applymap(lambda x: ILLEGAL_CHARACTERS_RE.sub('', str(x)) if isinstance(x, str) else x)
    with pd.ExcelWriter(Path(file_path).name + '.xlsx') as writer:
        df_module.to_excel(writer, sheet_name='ModuleInfo', index=False)
        df_funcs.to_excel(writer, sheet_name='FuncsInfo', index=False)
        df_strings.to_excel(writer, sheet_name='StringsInfo', index=False)

    

if __name__ == "__main__":
    main()

