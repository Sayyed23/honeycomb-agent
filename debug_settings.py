
from config.settings import settings
import os

print(f"Current working directory: {os.getcwd()}")
print(f"Environment variable DATABASE_URL: {os.environ.get('DATABASE_URL')}")
print(f"Settings database URL: {settings.database.url}")
print(f"Is SQLite? {settings.database.url.startswith('sqlite')}")
