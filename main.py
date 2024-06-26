import subprocess
import db
import pandas as pd
import os
import base64
import ppdeep
import argparse
import logging
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE

logging.basicConfig(
    handlers=[logging.FileHandler(filename='log.txt', encoding='utf-8')], format='%(levelname)s - %(message)s', level=logging.INFO
)

logger = logging.getLogger("logger")


def add_data_to_db(idahunt_path):
    files = os.listdir('./test_parse')
    if not len(files):
        logger.info("To start parsing, you need to put files in test_parse directory")
        return
    logger.info("Start parsing")
    p = subprocess.run(['python', f'{idahunt_path}/idahunt.py', '--inputdir', './test_parse', '--analyse', '--scripts', 'parse.py'],
                      text=True, capture_output=True, check=True)


def search_dependencies(idahunt_path):
    files = os.listdir('./test_dependencies')
    if not len(files):
        logger.info("To start analysis, you need to put files in test_dependencies directory")
        return
    logger.info("Start dependencies search")
    p = subprocess.run(['python', f'{idahunt_path}/idahunt.py' ,'--inputdir', './test_dependencies', '--analyse', '--scripts',  'search_dependencies.py'],
                        text=True, capture_output=True, check=True)
    return


def analyze_funcs(result):
    logger.info("Start search of known functions")
    for_del = []
    new_row = []
    for row in result:
        flag = 1
        data = db.execute_postgres_command("SELECT * FROM Functions WHERE jarowinkler(CAST(FunctionHash_ssdeep AS TEXT), '" + row['FunctionHash_ssdeep'] + "') >= 0.9 \
                                            OR (jarowinkler(CAST(FunctionHash_tlsh AS TEXT), '" + row['FunctionHash_tlsh'] + "') >= 0.9\
                                            AND FunctionHash_tlsh != 'TNULL');")
        confidence = 0
        if(len(data) == 0):
            flag = 0
            data = db.execute_postgres_command("SELECT * FROM Functions WHERE FunctionRefs = " + str(row['FunctionRefs']) +
                                           " AND FunctionArgsCount = " + str(row['FunctionArgsCount']) + 
                                           " AND FunctionCallCount = " + str(row['FunctionCallCount']) + 
                                           " AND FunctionJmpCount = " + str(row['FunctionJmpCount']) + ";")
        if (len(data) != 0):
            data = set(data)
            for element in data:
                confidence = 0
                if(flag):
                    if(element[6] == row['FunctionHash_sha256'] and element[5] == row['FunctionHash_md5']): confidence = 1
                    else: confidence = 0.9
                else:
                    if(element[4] == row['FunctionSize']): confidence += 0.1
                    if(element[11] == row['FunctionJmpCount']): confidence += 0.1
                    if(element[12] == row['FunctionCallCount']): confidence += 0.1
                    if(element[9] == row['FunctionRefs']): confidence += 0.1
                    if(element[10] == row['FunctionArgsCount']): confidence += 0.1
                key_tuple = tuple([element[1], element[2], element[3], element[4],
                                    element[5], element[6], element[7], element[8],
                                    element[9], element[10], element[11], element[12]])
                existing_entry = next((entry for entry in new_row if entry[:12] == key_tuple), None)
                if existing_entry is None:
                    new_row.append(tuple([element[1], element[2], element[3], element[4],
                                    element[5], element[6], element[7], element[8],
                                    element[9], element[10], element[11], element[12],
                                    confidence, row['FuncName'], row['FunctionSize'], row['FunctionHash_md5'],
                                    row['FunctionHash_sha256'], row['FunctionHash_ssdeep'], row['FunctionHash_tlsh'],
                                    row['FunctionRefs'], row['FunctionArgsCount'], row['FunctionJmpCount'], 
                                    row['FunctionCallCount']]))
                else:
                    if (existing_entry[-1] < confidence): 
                        new_row.remove(existing_entry)
                        new_row.append(tuple([element[1], element[2], element[3], element[4],
                                    element[5], element[6], element[7], element[8],
                                    element[9], element[10], element[11], element[12],
                                    confidence, row['FuncName'], row['FunctionSize'], row['FunctionHash_md5'],
                                    row['FunctionHash_sha256'], row['FunctionHash_ssdeep'], row['FunctionHash_tlsh'],
                                    row['FunctionRefs'], row['FunctionArgsCount'], row['FunctionJmpCount'], 
                                    row['FunctionCallCount']]))

    result.sort(key=lambda x: x['Confidence'], reverse=True)
    new_row = set(new_row)
    # columns = ['FuncName', 'ModuleID', 
    #        'FuncOffset', 'FunctionSize', 
    #        'FunctionHash_md5', 'FunctionHash_sha256', 
    #        'FunctionHash_ssdeep', 'FunctionHash_tlsh',
    #        'FunctionRefs', 'FunctionArgsCount',
    #        'FunctionJmpCount', 'FunctionCallCount', 'Confidence'] 
    columns = ['DBFuncName', 'DBModuleID', 
           'DBFuncOffset', 'DBFunctionSize', 
           'DBFunctionHash_md5', 'DBFunctionHash_sha256', 
           'DBFunctionHash_ssdeep', 'DBFunctionHash_tlsh',
           'DBFunctionRefs', 'DBFunctionArgsCount',
           'DBFunctionJmpCount', 'DBFunctionCallCount', 'Confidence', 
           'FuncName', 'FunctionSize', 
           'FunctionHash_md5', 'FunctionHash_sha256', 
           'FunctionHash_ssdeep', 'FunctionHash_tlsh',
           'FunctionRefs', 'FunctionArgsCount',
           'FunctionJmpCount', 'FunctionCallCount']
    unique_rows = [pd.Series(row, index=columns) for row in new_row]
    unique_rows.sort(key=lambda x: x['Confidence'], reverse=True)
    return unique_rows


def analyze_strings(result):
    logger.info("Start search of known strings")
    for_del = []
    for row in result:
        string = str(row['Str']).encode('utf-8')
        string_base64 = base64.b64encode(string).decode('utf-8')
        data = db.execute_postgres_command("SELECT * FROM Strings WHERE Str = '" + string_base64 + "';") 
        if(not data): for_del.append(row)
    for i in for_del: result.remove(i)
    return result


def analyze_similarity(idahunt_path):
    files = os.listdir('./test_bindiff')
    if not len(files):
        logger.info("To start analysis, you need to put files in test_bindiff directory")
        return
    logger.info("Start parsing")
    p = subprocess.run(['python', f'{idahunt_path}/idahunt.py' ,'--inputdir', './test_bindiff', '--analyse', '--scripts',  'bindiff.py'], 
                     text=True, capture_output=True, check=True)

    files = os.listdir('./test_bindiff')
    result_m = []
    result_f = []
    result_s = []
    flag = 0
    flag_1 = 0
    for file in files:
        if(file[-4:] != "xlsx"): continue
        print(file)
        df_modules = pd.read_excel('./test_bindiff/' + file, sheet_name = 'ModuleInfo')
        df_funcs = pd.read_excel('./test_bindiff/' + file, sheet_name = 'FuncsInfo')
        df_strings = pd.read_excel('./test_bindiff/' + file, sheet_name = 'StringsInfo')
        data_as_dicts_m = df_modules.to_dict(orient='records')
        data_as_dicts_f = df_funcs.to_dict(orient='records')
        data_as_dicts_s = df_strings.to_dict(orient='records')

        if(not flag):
            result_m = data_as_dicts_m
            result_f = data_as_dicts_f
            result_s = data_as_dicts_s
            flag = 1
        else:
            result_m.append(data_as_dicts_m[0])
            for_del = []
            for row in result_f:
                #print(row)
                flag_1 = 0
                for item in data_as_dicts_f:
                    if((ppdeep.compare(row['FunctionHash_ssdeep'], item['FunctionHash_ssdeep']) >= 80) or (row['FunctionHash_tlsh'] == item['FunctionHash_tlsh'] and row['FunctionHash_tlsh'] != 'TNULL')): 
                        flag_1 = 1
                        break
                if(not flag_1): for_del.append(row)
            for i in for_del: result_f.remove(i)
            for_del = []
            for row in result_s:
                flag_1 = 0
                for item in data_as_dicts_s:
                    if(row['Str'] == item['Str']): 
                        flag_1 = 1
                        break
                if(not flag_1): for_del.append(row)
            for i in for_del: result_s.remove(i)
    result_f = analyze_funcs(result_f)
    result_s = analyze_strings(result_s)
    df_modules = pd.DataFrame(result_m)
    df_funcs = pd.DataFrame(result_f)
    df_strings = pd.DataFrame(result_s)
    df_strings = df_strings[~df_strings.applymap(lambda x: ILLEGAL_CHARACTERS_RE.search(str(x))).any(axis=1)]
    with pd.ExcelWriter('./test_bindiff/result.xlsx') as writer:
        df_modules.to_excel(writer, sheet_name='ModuleInfo', index=False)
        df_funcs.to_excel(writer, sheet_name='FuncsInfo', index=False)
        df_strings.to_excel(writer, sheet_name='StringsInfo', index=False)
    if(not (len(df_modules) and len(df_funcs) and len(df_strings))): logger.info("There is no data to put in xlsx")
    else: logger.info("Your data is in result.xlsx in test_bindiff directory")
    return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--idahunt-path', type=str, required=True, help='Path to the idahunt directory')
    
    args = parser.parse_args()
    db.init()
    print("This program can solve the following 3 tasks:")
    print("1 - Adding data into database of known libraries and functions")
    print("2 - Search for external dependencies in an executable file")
    print("3 - Analyze the similarity of known executable files ")
    print("0 - Exit")
    
    while (1):
        print("Your choice:")
        choice = int(input())
        if(choice == 0): break
        elif(choice == 1): add_data_to_db(args.idahunt_path)
        elif(choice == 2): search_dependencies(args.idahunt_path)
        elif(choice == 3): analyze_similarity(args.idahunt_path)
        else: print("Try again")


if __name__ == '__main__':
    main()