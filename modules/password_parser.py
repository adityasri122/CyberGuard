import csv
import json
from pathlib import Path

def parse_password_file(file_path):
    """
    Parses a password export file (CSV or JSON) and returns a list of logins.
    
    Each login is a dictionary: {"url": "...", "username": "...", "password": "..."}
    """
    file_path = Path(file_path)
    file_extension = file_path.suffix.lower()
    
    if file_extension == '.csv':
        return _parse_csv(file_path)
    elif file_extension == '.json':
        return _parse_json(file_path)
    else:
        # If we don't recognize the format, raise an error
        raise ValueError(f"Unsupported file format: {file_extension}")

def _parse_csv(file_path):
    """Parses a CSV file (assumes Chrome/Edge export format)."""
    logins = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Use csv.reader to handle commas inside quotes
            reader = csv.reader(f)
            
            # Read the header to find the columns we need
            try:
                header = next(reader)
            except StopIteration:
                raise ValueError("File is empty.")
                
            # Find the column indices for 'url', 'username', and 'password'
            # (Column names can vary slightly)
            try:
                url_index = next(i for i, col in enumerate(header) if 'url' in col.lower())
                user_index = next(i for i, col in enumerate(header) if 'username' in col.lower())
                pass_index = next(i for i, col in enumerate(header) if 'password' in col.lower())
            except StopIteration:
                raise ValueError("CSV header is missing 'url', 'username', or 'password' columns.")

            # Read the rest of the rows
            for row in reader:
                if len(row) > max(url_index, user_index, pass_index):
                    logins.append({
                        "url": row[url_index],
                        "username": row[user_index],
                        "password": row[pass_index]
                    })
            
            if not logins:
                print("Warning: CSV file was read, but no logins were found.")
                
            return logins
            
    except Exception as e:
        print(f"Error reading CSV: {e}")
        raise ValueError(f"Could not parse CSV file. Error: {e}")

def _parse_json(file_path):
    """
    Parses a JSON file.
    Assumes a simple list of objects: [{"url": "...", "username": "...", "password": "..."}]
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
            # Basic validation: Is it a list of dictionaries?
            if not isinstance(data, list):
                raise ValueError("JSON file is not a list of logins.")
            
            if data and not (isinstance(data[0], dict) and 'url' in data[0]):
                 raise ValueError("JSON format not recognized. Expected a list of objects with 'url', 'username', 'password'.")
            
            return data
            
    except json.JSONDecodeError:
        raise ValueError("File is not valid JSON.")
    except Exception as e:
        print(f"Error reading JSON: {e}")
        raise ValueError(f"Could not parse JSON file. Error: {e}")