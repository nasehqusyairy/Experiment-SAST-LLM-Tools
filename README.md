# Experiment-SAST-LLM-Tools

> This repository contains scripts and resources for running experiments on SAST (Static Application Security Testing) using LLMs (Large Language Models). It is designed for TFM research and includes tools for prompt engineering, experiment automation, and result analysis.

## Folder Structure

- `runExperiment.py`: Main script to run experiments on Java code using LLMs. Accepts parameters for input directory, models, iterations, description, backend, and optional max files and prompt template.
- `generateCSV.py`: Processes experiment output files and generates CSV summaries for further analysis.
- `cleanReferences.py`: Utility to update Java servlet annotations for benchmarking.
- `expectedOutputLLM.txt`: Shows the expected output schema for LLM responses.
- `OWASP Benchmark Extension/CSVLLM.java`: Java class for parsing CSV results and integrating with OWASP Benchmark.
- `Prompt/FirstPrompt.py`: Contains the default prompt template for LLM-based vulnerability analysis.
- `Prompt/SecondPrompt.py`: Alternative prompt template with additional static analysis context and FP/TP classification.

## Usage

### Run Experiment
```bash
python runExperiment.py <java_directory> <model1,model2> <iterations> <description> <backend> [max_files] [prompt_template_file]
```
- `<java_directory>`: Path to Java source files to analyze
- `<model1,model2>`: Comma-separated list of LLM models
- `<iterations>`: Number of experiment iterations
- `<description>`: Description of the experiment
- `<backend>`: Backend service for LLM (e.g., Gemini, Ollama)
- `[max_files]`: (Optional) Maximum number of files to process
- `[prompt_template_file]`: (Optional) Path to custom prompt template

### Generate CSV Summary
```bash
python generateCSV.py <input_folder>
```
- `<input_folder>`: Folder containing experiment output files

## Prompts
- `Prompt/FirstPrompt.py`: Standard prompt for vulnerability detection
- `Prompt/SecondPrompt.py`: Enhanced prompt with static analysis and FP/TP classification

## Java Extension
- `OWASP Benchmark Extension/CSVLLM.java`: Integrates experiment results with OWASP Benchmark for further analysis

## Output Schema
See `expectedOutputLLM.txt` for the expected format of LLM responses.

## License
This project is for academic/research use.