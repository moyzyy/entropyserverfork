import sys
import re
import os

def remove_comments(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " " # note: a space and not an empty string
        else:
            return s
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)

def process_file(filepath):
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            
        new_content = remove_comments(content)
        
        # simple cleanup of empty lines created
        lines = [line for line in new_content.splitlines() if line.strip()]
        final_content = '\n'.join(lines) + '\n'
        
        with open(filepath, 'w') as f:
            f.write(final_content)
        print(f"Processed: {filepath}")
    except Exception as e:
        print(f"Error processing {filepath}: {e}")

if __name__ == "__main__":
    for file_path in sys.argv[1:]:
        process_file(file_path)
