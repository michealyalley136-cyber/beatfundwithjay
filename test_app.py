import os
os.environ['DEV_OWNER_PANEL_PASS'] = 'dev123'

try:
    from app import app
    print("[OK] App imported successfully!")
    print(f"[OK] App name: {app.name}")
    print("[OK] Ready to run on http://localhost:5000")
except Exception as e:
    print(f"[ERROR] Error: {e}")
    import traceback
    traceback.print_exc()
