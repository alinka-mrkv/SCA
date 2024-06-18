import subprocess
import db
import pandas as pd
import os
import base64
import ppdeep
import argparse


def add_data_to_db(idahunt_path):
    p = subprocess.run(['python', f'{idahunt_path}/idahunt.py', '--inputdir', './test_parse', '--analyse', '--scripts', 'parse.py'],
                      text=True, capture_output=True, check=True)


def search_dependencies(idahunt_path):
    p = subprocess.run(['python', f'{idahunt_path}/idahunt.py' ,'--inputdir', './test_dependencies', '--analyse', '--scripts',  'search_dependencies.py'],
                        text=True, capture_output=True, check=True)
    return


def analyze_funcs(result):
    for_del = []
    new_row = []
    for row in result:
        flag = 1
        data = db.execute_postgres_command("SELECT * FROM Functions WHERE jarowinkler(CAST(FunctionHash_ssdeep AS TEXT), '" + row['FunctionHash_ssdeep'] + "') >= 0.8 \
                                            AND (jarowinkler(CAST(FunctionHash_tlsh AS TEXT), '" + row['FunctionHash_tlsh'] + "') >= 0.8\
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
                new_row.append(tuple([element[1], element[2],
                                  element[3], element[4],
                                  element[5], element[6],
                                  element[7], element[8],
                                  element[9], element[10],
                                  element[11], element[12],
                                  confidence]))

    result.sort(key=lambda x: x['Confidence'], reverse=True)
    new_row = set(new_row)
    columns = ['FuncName', 'ModuleID', 
           'FuncOffset', 'FunctionSize', 
           'FunctionHash_md5', 'FunctionHash_sha256', 
           'FunctionHash_ssdeep', 'FunctionHash_tlsh',
           'FunctionRefs', 'FunctionArgsCount',
           'FunctionJmpCount', 'FunctionCallCount', 'Confidence'] 
    unique_rows = [pd.Series(row, index=columns) for row in new_row]
    unique_rows.sort(key=lambda x: x['Confidence'], reverse=True)
    return unique_rows


def analyze_strings(result):
    for_del = []
    for row in result:
        string = str(row['Str']).encode('utf-8')
        string_base64 = base64.b64encode(string).decode('utf-8')
        data = db.execute_postgres_command("SELECT * FROM Strings WHERE Str = '" + string_base64 + "';") 
        if(not data): for_del.append(row)
    for i in for_del: result.remove(i)
    return result


def analyze_similarity(idahunt_path):
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
    with pd.ExcelWriter('./test_bindiff/result.xlsx') as writer:
        df_modules.to_excel(writer, sheet_name='ModuleInfo', index=False)
        df_funcs.to_excel(writer, sheet_name='FuncsInfo', index=False)
        df_strings.to_excel(writer, sheet_name='StringsInfo', index=False)
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