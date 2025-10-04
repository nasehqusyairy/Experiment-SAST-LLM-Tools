import os
import csv
import re
import sys
import json
import requests
import time
from pathlib import Path
from datetime import datetime
from typing import List
from pydantic import BaseModel, Field
from typing import Literal
  
 os.environ["GEMINI_API_KEY"] = "x"  # Set your Gemini API key here
  
 # --- Default prompt ---
 OLLAMA_API_URL = "https://x/api/generate" # Set your Ollama API URL here
 DEFAULT_PROMPT_TEMPLATE = (
     "You are a security assistant. ONLY answer the following 3 questions. No reasoning, no explanation.\n"
     "Use angle brackets `<...>` only in your internal response, but the final JSON output must NOT include them.\n"
     "Strictly follow this format:\n\n"
     "Q1: Is there any vulnerability? <TRUE or FALSE>\n"
     "Q2: What CWE category? <pathtraver | hash | trustbound | crypto | cmdi | sqli | weakrand | ldapi | xss | securecookie | xpathi>\n"
     "Q3: Which line number has the vulnerability? <Line>\n"
     "Q4: Which is the CWE of the vulnerability? <CWE>\n\n"
     "Analyze the following code:\n"
     "{java_code}"
     "\n\n"
 )
  
  # output schema
 class result(BaseModel):
     Q1: bool
     Q2: str
     Q3: int
     Q4: int
  
  # folder to save results
 OUTPUT_DIR = Path("result")
  
 def read_file(file_path: Path) -> str:
     with open(file_path, "r", encoding="utf-8") as f:
         return f.read()
  # Call Ollama API
 def call_ollama_generate(model: str, prompt: str, api_url: str = OLLAMA_API_URL) -> str:
     try:
         headers = {"Content-Type": "application/json"}
         # temperature 0 for deterministic output
         data = {
             "model": model,
             "prompt": prompt,
             "stream": False,
             "temperature": 0.0,
             "top_p": 0.9,
             "top_k": 20,
             "repeat_penalty": 1.0,
             "format": result.model_json_schema(),
         }
         response = requests.post(api_url, headers=headers, data=json.dumps(data))
         response.raise_for_status()
         body = response.json()
         return body.get("response", str(body))
     except Exception as e:
         print(f"❌ API error: {e}")
         return f"[ERROR] {str(e)}"
     
  # Find all Java files in a directory
 def find_java_files(directory: Path, max_files: int = None) -> List[Path]:
     files = sorted(directory.rglob("*.java"))  # Ensures consistent order
     return files[:max_files] if max_files else files

# Sanitize filename components
 def sanitize_filename_component(text: str) -> str:
     return text.replace(":", "-").replace(".", "-").replace("/", "-").replace("\\", "-").replace(" ", "_")

# Call Gemini API  
 def call_gemini_generate(prompt: str, model: str = "gemini-pro") -> str:
     try:
         api_key = os.getenv("GEMINI_API_KEY")
         if not api_key:
             raise EnvironmentError("❌ Missing GEMINI_API_KEY environment variable.")
         
         url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
         headers = {"Content-Type": "application/json"}
         data = {
             "contents": [
                 {
                     "parts": [{"text": prompt}]
                 }
             ]
         }
         response = requests.post(url, headers=headers, json=data)
         response.raise_for_status()
         candidates = response.json().get("candidates", [])
         return candidates[0]["content"]["parts"][0]["text"] if candidates else "[NO_RESPONSE]"
     except Exception as e:
         print(f"❌ Gemini API error: {e}")
         return f"[ERROR] {str(e)}"
  
  # Analyze all Java files with multiple models
 def analyze_all_java_files_with_multiple_models(
     directory: Path,
     models: List[str],
     iterations: int,
     prompt_template: str,
     description: str,
     max_files: int = None,
     backend: str = "gemini"
 ):
     java_files = find_java_files(directory, max_files)
     print(f"📁 Found {len(java_files)} Java files in `{directory}`.")
     RATE_LIMIT_INTERVAL = 6
     last_call_time = 0
  
     OUTPUT_DIR.mkdir(exist_ok=True)
  
     sanitized_description = sanitize_filename_component(description)
  
     for model in models:
         sanitized_model = sanitize_filename_component(model)
         print(f"\n🚀 Testing model: {model} (sanitized: {sanitized_model})")
  
         for run_index in range(1, iterations + 1):
             iteration_tag = f"run{run_index}of{iterations}"
             print(f"\n🔁 Iteration {run_index}/{iterations}")
  
             for idx, java_file in enumerate(java_files, 1):
                 print(f"📤 [{idx}/{len(java_files)}] Sending `{java_file}` to model `{model}` (iteration {run_index})...")
                 java_code = read_file(java_file)
                 prompt = prompt_template.format(java_code=java_code)
  
                 base_filename = f"{java_file.stem}-{sanitized_model}-{sanitized_description}-run1of{iterations}"
                 base_filename_current = f"{java_file.stem}-{sanitized_model}-{sanitized_description}-{iteration_tag}"
  
                 # outfile generation based on iteration
                 output_file_first = OUTPUT_DIR / f"{base_filename}-output.txt"
                 output_file_current = OUTPUT_DIR / f"{base_filename_current}-output.txt"
                 input_file_current = OUTPUT_DIR / f"{base_filename_current}-input.txt"
  
                 if run_index > 1 and not output_file_first.exists():
                     print(f"⚠️ First iteration output missing, skipping: {output_file_current}")
                     continue
  
                 if output_file_current.exists():
                     print(f"⏭️ Output already exists, skipping: {output_file_current}")
                     continue
  
                 with open(input_file_current, "w", encoding="utf-8") as f:
                     f.write(prompt)
                 print(f"✅ Saved input to: {input_file_current}")
  
                 if backend == "ollama":
                     result = call_ollama_generate(model, prompt)
                 elif backend == "gemini":
                     now = time.time()
                     elapsed = now - last_call_time
                     if elapsed < RATE_LIMIT_INTERVAL:
                         wait_time = RATE_LIMIT_INTERVAL - elapsed
                         print(f"⏳ Waiting {wait_time:.2f}s to respect rate limit...")
                         time.sleep(wait_time)
                     last_call_time = time.time()
                     result = call_gemini_generate(prompt, model)
                 else:
                     print(f"❌ Unsupported backend: {backend}")
                     result = "[ERROR] Unsupported backend"
  
                 with open(output_file_current, "w", encoding="utf-8") as f:
                     f.write(result)
                 print(f"✅ Saved output to: {output_file_current}")
  
  # Main function 
 def main():
     if len(sys.argv) < 6:
         print("Usage: python runExperiment.py <java_directory> <model1,model2> <iterations> <description> <backend> [max_files] [prompt_template_file]")
         sys.exit(1)
  
     java_directory = Path(sys.argv[1])
     models = sys.argv[2].split(",")
  
     try:
         iterations = int(sys.argv[3])
     except ValueError:
         print("❌ Iterations must be an integer.")
         sys.exit(1)
  
     description = sys.argv[4]
     backend = sys.argv[5]
  
     if backend not in ("gemini", "ollama"):
         print("❌ Backend must be either 'gemini' or 'ollama'.")
         sys.exit(1)
  
     max_files = None
     if len(sys.argv) > 6:
         try:
             max_files = int(sys.argv[6])
         except ValueError:
             print("❌ max_files must be an integer.")
             sys.exit(1)
  
     prompt_template_file = Path(sys.argv[7]) if len(sys.argv) > 7 else None
  
     if not java_directory.is_dir():
         print(f"❌ Not a directory: {java_directory}")
         sys.exit(1)
  
     if prompt_template_file and prompt_template_file.exists():
         prompt_template = read_file(prompt_template_file)
     else:
         prompt_template = DEFAULT_PROMPT_TEMPLATE
  
    # Time tracking
     start_time = datetime.now()
     print(f"\n⏱️ Started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
     t0 = time.time()
  
     analyze_all_java_files_with_multiple_models(
         java_directory, models, iterations, prompt_template, description, max_files, backend
     )
  
     end_time = datetime.now()
     duration = time.time() - t0
     print(f"\n✅ Finished at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
     print(f"⌛ Duration: {duration:.2f} seconds")
    #Time tracking off

 if __name__ == "__main__":
     main()
