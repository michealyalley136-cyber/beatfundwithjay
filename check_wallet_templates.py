import os

# Start from the folder where this script lives
ROOT = os.path.dirname(os.path.abspath(__file__))
TARGET = "wallet_ledger.html"

print(f"Searching under: {ROOT}")
print(f"Looking for: {TARGET}")
print("-" * 50)

found = False

for dirpath, dirnames, filenames in os.walk(ROOT):
    if TARGET in filenames:
        found = True
        full_path = os.path.join(dirpath, TARGET)
        print(f"✅ Found: {full_path}")

if not found:
    print("❌ wallet_ledger.html was NOT found anywhere under this folder.")
