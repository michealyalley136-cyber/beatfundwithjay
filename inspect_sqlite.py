import sqlite3
import os

# Connect to SQLite database
db_path = os.path.join('instance', 'app.db')
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Get all table names
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

print("Tables in SQLite database:")
for table in tables:
    table_name = table[0]
    print(f"\n{table_name}:")

    # Get column info (handle reserved keywords)
    try:
        if table_name == 'order':
            cursor.execute(f'PRAGMA table_info("{table_name}")')
        else:
            cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()
        print(f"  Columns: {[col[1] for col in columns]}")

        # Get row count
        cursor.execute(f'SELECT COUNT(*) FROM "{table_name}"')
        count = cursor.fetchone()[0]
        print(f"  Rows: {count}")

        # Show sample data if table has users
        if 'user' in table_name.lower() and count > 0:
            cursor.execute(f'SELECT * FROM "{table_name}" LIMIT 3')
            rows = cursor.fetchall()
            print("  Sample data:")
            for row in rows:
                print(f"    {row}")
    except Exception as e:
        print(f"  Error inspecting table: {e}")

conn.close()