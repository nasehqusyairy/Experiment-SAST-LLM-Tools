import csv
import glob
import os
import re
import sys
import json
from collections import defaultdict
 # this script processes output files from an experiment and generates CSV summaries
 # Function to extract Q1, Q2, and Q4 answers from file content
def extract_q_answers(content):
    q1, q2, q4 = "", "", ""
 
    try:
        # Try to parse the first JSON object in the content
        json_match = re.search(r'\{.*?\}', content, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group(0))
            q1 = str(data.get("Q1", "")).upper() 
            q2 = data.get("Q2", "").strip().lower()
            q4 = str(data.get("Q4", ""))
            q4_match = re.search(r'\d+', q4)
            q4 = q4_match.group() if q4_match else ""
            return q1, q2, q4
    except Exception:
        pass
 
    # Fallback to manual parsing
    for line in content.splitlines():
        line = line.strip()
 
        if line.lower().startswith("q1") and not q1:
            match = re.search(r'\b(TRUE|FALSE)\b', line, re.IGNORECASE)
            if match:
                q1 = match.group(1).upper()
 
        elif line.lower().startswith("q2") and not q2:
            match = re.search(r'Q2[^:]*:\s*(.*)', line, re.IGNORECASE)
            if match:
                parts = match.group(1).strip().split()
                if parts:
                    candidate = parts[-1].lower()
                    if candidate not in ["what", "none", ""]:
                        q2 = candidate
 
        elif line.lower().startswith("q4") and not q4:
            match = re.search(r'\d+', line)
            if match:
                q4 = match.group()
 
    return q1, q2, q4
 
 # Function to parse the filename and extract test name and model
def parse_filename(filepath):
    filename = os.path.basename(filepath).replace('.txt', '')
    parts = filename.split('-')
 
    if len(parts) < 5 or not filename.startswith("BenchmarkTest"):
        return None
 
    test_name = parts[0]
    model = '-'.join(parts[1:-1])  # up to "runXofY"
    return test_name, model

 # Main function
def main():
    if len(sys.argv) != 2:
        print("Usage: python generateCSV.py <input_folder>")
        sys.exit(1)
 
    input_folder = sys.argv[1]
    os.makedirs("results", exist_ok=True)
 
    files = glob.glob(os.path.join(input_folder, '*output.txt'))
 
    if not files:
        print("No matching files found.")
        sys.exit(1)
 
    model_data = defaultdict(list)
    
    # Process each file
    for filepath in files:
        parsed = parse_filename(filepath)
        if not parsed:
            print(f"Skipping invalid filename: {filepath}")
            continue
 
        test_name, model = parsed
 
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
 
        q1, q2, q4 = extract_q_answers(content)
        model_data[model].append([test_name, q1, q2, q4])
 
    # Save results to CSV files
    for model, rows in model_data.items():
        output_csv = os.path.join("results", f"{model}.csv")
        with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["# test name", "real vulnerability", "category", "cwe"])
            writer.writerows(rows)
 
        print(f"✅ Saved: {output_csv}")
 
if __name__ == "__main__":
    main()
