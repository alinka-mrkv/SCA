import subprocess
import db
import pymap


def add_data_to_db():
    p = subprocess.run(['python', '../idahunt/idahunt.py' ,'--inputdir', '../idahunt/test', '--scripts',  'parse_modules.py'], text=True, capture_output=True, check=True)
    p = subprocess.run(['python', '../idahunt/idahunt.py' ,'--inputdir', '../idahunt/test', '--scripts',  'parse_funcs.py'], text=True, capture_output=True, check=True)
    p = subprocess.run(['python', '../idahunt/idahunt.py' ,'--inputdir', '../idahunt/test', '--scripts',  'parse_strings.py'], text=True, capture_output=True, check=True)
    return


def search_dependencies():
    return


def analyze_similarity():
    return


def main():
    #if(db.execute_postgres_command("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = \'" + db.db_db +"\');") == False): db.init()
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
        elif(choice == 1): add_data_to_db()
        elif(choice == 2): search_dependencies()
        elif(choice == 3): analyze_similarity()
        else: print("Try again")


if __name__ == '__main__':
    main()