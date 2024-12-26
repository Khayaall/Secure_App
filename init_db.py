import sqlite3

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create the users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL)''')
    
    # Insert some test users (plaintext passwords)
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123')")
    cursor.execute("INSERT INTO users (username, password) VALUES ('user1', 'mypassword')")
    
    conn.commit()
    conn.close()
    print("Database initialized with test users.")

if __name__ == "__main__":
    init_db()
