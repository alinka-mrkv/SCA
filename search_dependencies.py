import idautils
import idc
import db
import hashlib
import ida_nalt
from pathlib import Path
import pandas as pd
import ppdeep
import tlsh
from help_module import *


file_path = ida_nalt.get_input_file_path() 

columns = ['DBFuncName', 'DBModuleID', 
           'DBFuncOffset', 'DBFunctionSize', 
           'DBFunctionHash_md5', 'DBFunctionHash_sha256', 
           'DBFunctionHash_ssdeep', 'DBFunctionHash_tlsh',
           'DBFunctionRefs', 'DBFunctionArgsCount',
           'DBFunctionJmpCount', 'DBFunctionCallCount',  
           'FuncName', 'FunctionSize', 
           'FunctionHash_md5', 'FunctionHash_sha256', 
           'FunctionHash_ssdeep', 'FunctionHash_tlsh',
           'FunctionRefs', 'FunctionArgsCount',
           'FunctionJmpCount', 'FunctionCallCount', 'Confidence'] 
new_row = set()

with open('../log.txt', 'a', encoding='utf-8') as file:
    file.write("INFO - Start parsing functions\n")

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
        flag = 1
        data = db.execute_postgres_command("SELECT * FROM Functions WHERE jarowinkler(CAST(FunctionHash_ssdeep AS TEXT), '" + func_hash_ssdeep + "') >= 0.9 \
                                            OR (jarowinkler(CAST(FunctionHash_tlsh AS TEXT), '" + func_hash_tlsh + "') >= 0.9\
                                            AND FunctionHash_tlsh != 'TNULL');")

        if(len(data) == 0):
            flag = 0
            data = db.execute_postgres_command("SELECT * FROM Functions WHERE FunctionRefs = " + str(func_code_refs) +
                                           " AND FunctionArgsCount = " + str(func_args_count) + 
                                           " AND FunctionCallCount = " + str(func_call_count) + 
                                           " AND FunctionJmpCount = " + str(func_jmp_count) + ";")
        if (len(data) != 0):
            data = set(data)
            # print(function_name, function_size, func_hash_md5, func_hash_sha256, 
            #                         func_hash_ssdeep, func_hash_tlsh, func_code_refs, func_args_count, 
            #                         func_jmp_count, func_call_count)
            # print("\n")
            for element in data:
                confidence = 0
                if(flag):
                    if(element[6] == str(func_hash_sha256) and element[5] == str(func_hash_md5)): confidence = 1
                    else: confidence = 0.9
                else:
                    if(element[4] == function_size): confidence += 0.1
                    if(element[11] == func_jmp_count): confidence += 0.1
                    if(element[12] == func_call_count): confidence += 0.1
                    if(element[9] == func_code_refs): confidence += 0.1
                    if(element[10] == func_args_count): confidence += 0.1
                new_row.add(tuple([element[1], element[2], element[3], element[4],
                                    element[5], element[6], element[7], element[8],
                                    element[9], element[10], element[11], element[12], 
                                    function_name, function_size, func_hash_md5, func_hash_sha256, 
                                    func_hash_ssdeep, func_hash_tlsh, func_code_refs, func_args_count, 
                                    func_jmp_count, func_call_count, confidence]))
                key_tuple = tuple([element[1], element[2], element[3], element[4],
                                    element[5], element[6], element[7], element[8],
                                    element[9], element[10], element[11], element[12], 
                                    function_name, function_size, func_hash_md5, func_hash_sha256, 
                                    func_hash_ssdeep, func_hash_tlsh, func_code_refs, func_args_count, 
                                    func_jmp_count, func_call_count])
                existing_entry = next((entry for entry in new_row if entry[:22] == key_tuple), None)
                if existing_entry is None:
                    new_row.add(tuple([element[1], element[2], element[3], element[4],
                                    element[5], element[6], element[7], element[8],
                                    element[9], element[10], element[11], element[12], 
                                    function_name, function_size, func_hash_md5, func_hash_sha256, 
                                    func_hash_ssdeep, func_hash_tlsh, func_code_refs, func_args_count, 
                                    func_jmp_count, func_call_count, confidence]))
                else:
                    if (existing_entry[-1] < confidence): 
                        new_row.remove(existing_entry)
                        new_row.add(tuple([element[1], element[2], element[3], element[4],
                                    element[5], element[6], element[7], element[8],
                                    element[9], element[10], element[11], element[12], 
                                    function_name, function_size, func_hash_md5, func_hash_sha256, 
                                    func_hash_ssdeep, func_hash_tlsh, func_code_refs, func_args_count, 
                                    func_jmp_count, func_call_count, confidence]))

unique_rows = [pd.Series(row, index=columns) for row in new_row]
unique_rows.sort(key=lambda x: x['Confidence'], reverse=True)
df = pd.DataFrame(unique_rows, columns=columns)
max_rows_per_sheet = 1048575
with pd.ExcelWriter(Path(file_path).name + '.xlsx') as writer:
    sheet_number = 0  
    
    for i in range(0, len(df), max_rows_per_sheet):
        part_df = df.iloc[i:i+max_rows_per_sheet]
        part_df.to_excel(writer, sheet_name=f'DependenciesInfo_{sheet_number}', index=False)

        sheet_number += 1
    #df.to_excel(writer, sheet_name='DependenciesInfo', index=False)
with open('../log.txt', 'a', encoding='utf-8') as file:
    if(not len(df)): file.write("INFO - There is no data to put in xlsx\n")
    else: file.write("INFO - Your data is in " + Path(file_path).name + ".xlsx in test_dependencies directory")