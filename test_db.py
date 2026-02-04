from dotenv import load_dotenv
load_dotenv()

from app import app, db
print('App and DB imported successfully')

with app.app_context():
    print('App context created')
    try:
        # Test database connection
        with db.engine.connect() as conn:
            conn.execute(db.text('SELECT 1'))
        print('Database connection successful')
    except Exception as e:
        print(f'Database connection failed: {e}')