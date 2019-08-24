import sqlite3
from sqlite3 import Error
 
# http://www.sqlitetutorial.net/sqlite-python/creating-database/
 
def create_connection(db_file):
    """ create a database connection to a SQLite database """
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error:
        pass

    return None


def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)


def get_dictionary_form(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM members")
    members = cur.fetchall()
    cur.execute("SELECT * FROM snippets")
    snippets = cur.fetchall()
    columns = get_member_columns(conn)
    columns = [columns[1:][i][1] for i in range(0,len(columns[1:]))]

    dic = {}
    for member in members:
        dic[member[1]] = {}
        for i,column in enumerate(columns):
            dic[member[1]][column] = member[i+1]

        snips = []
        for snip in snippets:
            if member[1] == snip[2]:
                snips.append(snip[1])
        dic[member[1]]['snippets'] = snips
        
    return dic

def get_member_columns(conn):
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(members)")
    return cur.fetchall()


def create_member(conn, member):
    """
    Create a new member into the members table
    :param conn:
    :param member:
    :return: member id
    """

    sql = ''' INSERT INTO members(uid, name, pw, is_author, is_admin, private_snippet, icon, web_site, color)
              VALUES(?,?,?,?,?,?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, member)
    return cur.lastrowid


def create_snippet(conn, snippet):
    """
    Create a new member into the snippets table
    :param conn:
    :param snippet:
    :return: snippet id
    """
    sql = ''' INSERT INTO snippets(snippet, snippet_id)
              VALUES(?,?) '''
    cur = conn.cursor()
    cur.execute(sql, snippet)
    return cur.lastrowid


def is_table_empty(conn):
    sql = ''' SELECT count(*) FROM members '''
    cur = conn.cursor()
    cur.execute(sql)
    count = cur.fetchall()
    
    if count[0][0] > 0:
        return False
    else:
        return True

def update_member(conn, member):
    sql = ''' UPDATE members
              SET uid = ?,
                    name = ?,
                    pw = ?,
                    is_author = ?,
                    is_admin = ?,
                    private_snippet = ?,
                    icon = ?,
                    web_site = ?,
                    color = ?            
                WHERE id = ?'''
    cur = conn.cursor()
    cur.execute(sql, member)


def delete_snippet(conn, id):
    cur = conn.cursor()
    cur.execute("DELETE FROM snippets WHERE id=?", (id,))


def select_member_by_uid(conn, uid):
    """
    Query members by uid
    :param conn: the Connection object
    :param uid:
    :return cur.fetchall(): the member object
    """

    cur = conn.cursor()
    cur.execute("SELECT * FROM members WHERE uid=?", (uid,))
    return cur.fetchall()


def select_snippets_by_uid(conn, uid):
    """
    Query snippets by uid
    :param conn: the Connection object
    :param uid:
    :return cur.fetchall(): the member object
    """

    cur = conn.cursor()
    cur.execute("SELECT * FROM snippets WHERE snippet_id=?", (uid,))
    return cur.fetchall()


# maybe make a hella nice function for all these
# they kinda have this in gruyere.py
# See "_GetParameter"
def get_member_password(conn, uid):
    cur = conn.cursor()
    cur.execute("SELECT pw FROM members WHERE uid=?", (uid,))
    data = cur.fetchall()
    return data[0][0]


def is_member_admin(conn, uid):
    cur = conn.cursor()
    cur.execute("SELECT is_admin FROM members WHERE uid=?", (uid,))
    data = cur.fetchall()
    return data[0][0]


def is_member_author(conn, uid):
    cur = conn.cursor()
    cur.execute("SELECT is_author FROM members WHERE uid=?", (uid,))
    data = cur.fetchall()
    return data[0][0]


def main():

    sql_create_members_table = """ CREATE TABLE IF NOT EXISTS members (
                                        id integer PRIMARY KEY,
                                        uid text NOT NULL,
                                        name text,
                                        pw text NOT NULL,
                                        is_author integer,
                                        is_admin integer,
                                        private_snippet text,
                                        icon text,
                                        web_site text,
                                        color text
                                    ); """

    sql_create_snippets_table = """CREATE TABLE IF NOT EXISTS snippets (
                                    id integer PRIMARY KEY,
                                    snippet text NOT NULL,
                                    snippet_id text NOT NULL,
                                    FOREIGN KEY (snippet_id) REFERENCES members (uid)
                                );"""
    

    conn = create_connection("pythonsqlite.db")
    if conn is not None:
        
        create_table(conn, sql_create_members_table)
        create_table(conn, sql_create_snippets_table)
        
    else:
        print("Error! cannot create the database connection.")

main()