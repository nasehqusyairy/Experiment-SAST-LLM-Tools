import os
import re
 
# Function to replace the identifier in @WebServlet annotations with "/BT/"
def replace_identifier_with_BT(folder_path):
    # Regex to capture any @WebServlet(value = "/<identifier>/...")
    servlet_pattern = re.compile(r'@WebServlet\s*\(\s*value\s*=\s*"(/[^/]+/)')
 
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".java"):
                file_path = os.path.join(root, file)
 
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
 
                # Look for a matching @WebServlet line
                match = servlet_pattern.search(content)
                if match:
                    original_identifier = match.group(1)  # e.g., "/pathtraver-00/"
                    print(f"Updating {file_path}: Replacing '{original_identifier}' with '/BT/'")
                    updated_content = content.replace(original_identifier, '/BT/')
 
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(updated_content)
 
# Example usage
replace_identifier_with_BT('./src/main/java/org/owasp/benchmark/testcode')
