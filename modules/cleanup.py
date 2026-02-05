import shutil
from pathlib import Path

def secure_delete_folder(folder_path):
    """
    Deletes an entire folder and its contents.
    """
    folder_path = Path(folder_path)
    if folder_path.exists():
        try:
            # shutil.rmtree is the standard way to delete a folder
            shutil.rmtree(folder_path)
            print(f"DEBUG: Successfully cleaned up {folder_path}")
        except Exception as e:
            # This might fail if a file is still locked,
            # but it's good practice to try.
            print(f"DEBUG: Could not clean up {folder_path}. Error: {e}")
    else:
        print(f"DEBUG: Cleanup not needed, {folder_path} does not exist.")