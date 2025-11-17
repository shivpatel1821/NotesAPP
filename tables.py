import sqlite3
conn= sqlite3.connect("notes.db")
cursor = conn.cursor()

# cursor.execute('''CREATE TABLE note1 (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     topic TEXT NOT NULL,
#     notes TEXT NOT NULL,
#     user_id INTEGER,
#     FOREIGN KEY(user_id) REFERENCES users(id)
# );
# ''')


# cursor.execute('''create table register(
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     username varchar(20)  NOT NULL,
#     email varchar(30)  NOT NULL,
#     password varchar(6)  NOT NULL
    
# );
#                ''')


# cursor.execute('''
#                ALTER TABLE register ADD COLUMN google_id TEXT;
            

#                ''')


# cursor.execute('''
#                drop table register;
#                ''')

conn.close() 



# table='''
# create table note1(
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
# topic varchar(200),
# notes varchar(200)
# );
# '''
# cursor.execute('''create table note1(
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
# topic varchar(200),
# notes varchar(200)
# );
# ''')

# 

# cursor.execute('''drop table note1''')
# cursor.execute('''CREATE TABLE note1 (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     topic TEXT NOT NULL,
#     notes TEXT NOT NULL,
#     user_id INTEGER,
#     FOREIGN KEY(user_id) REFERENCES users(id)
# );
# ''')

# cursor.execute('''create table register(
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     username varchar(20)  NOT NULL,
#     email varchar(30)  NOT NULL,
#     password varchar(6)  NOT NULL
    
# );
#                ''')
# conn.close() 

