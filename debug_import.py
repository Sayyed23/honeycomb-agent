
import warnings
warnings.filterwarnings("ignore")

try:
    print("Attempting to import app.main...")
    from app.main import app
    print("Import successful!")
except Exception:
    traceback.print_exc()
