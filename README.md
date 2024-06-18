# SCA
A program to detect statically linked libraries (at the level of code functions) in an executable file in Windows and to analyze the similarity of two executable files

## Requirements
All you need to run this project is:
- Python 3
- IDA Pro 
- idahunt (you can get it here: https://github.com/nccgroup/idahunt)
- PostgreSQL
There is a requirements.txt where you can find Python modules you need to install
Also, you need to install pg_similarity extension for Postgresql (for example, using `sudo apt install postgresql-X-similarity`, where X - your Postgresql version)

## Preparing
First of all, you need to create your own database, and then fill .env file with information:
```
DB_HOST = address of host with PostgreSQL
DB_PORT = PostgreSQL port
DB_USER = user wuth privileges on your database
DB_PASSWORD = his password
DB_DATABASE = name of your database
```

## Usage
You can run the project as follows:

```
C:\SCA> python .\main.py -h
usage: main.py [-h] --idahunt-path IDAHUNT_PATH

optional arguments:
  -h, --help            show this help message and exit
  --idahunt-path IDAHUNT_PATH
                        Path to the idahunt directory
```

Then, you will see the message:
```
This program can solve the following 3 tasks:
1 - Adding data into database of known libraries and functions
2 - Search for external dependencies in an executable file
3 - Analyze the similarity of known executable files
0 - Exit
```

If you want to parse libraries for your database (1), you need to put these files in the `test_parse directory`. If your task is to find known dependencies in a binary file (2), place the examined file in `test_dependencies`.  If the goal is to find common known dependencies in several binary files (3), place them in `test_bindiff`.
