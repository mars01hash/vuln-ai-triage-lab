# Scripts Directory

This directory contains executable scripts to simplify common tasks like model training and pipeline execution across different operating systems.

## Files
* `train_model.bat` / `train_model.sh`: Automatically trains the ML TF-IDF + Logistic Regression CWE classifier model.
* `run_demo.bat` / `run_demo.sh`: Processes the sample findings dataset through the pipeline using the trained ML model.

## Usage
Run these commands from the root project directory:

**Windows (CMD/PowerShell):**
```cmd
# Train ML model
scripts\train_model.bat

# Run pipeline demo using trained ML model
scripts\run_demo.bat
```

**Linux/macOS:**
```bash
# Make executable
chmod +x scripts/*.sh

# Train ML model
./scripts/train_model.sh

# Run pipeline demo using trained ML model
./scripts/run_demo.sh
```

## Why it works
Manually typing long Python module commands with various flags (like `--input`, `--use-ml`, `--report`, etc.) can be tedious and prone to typos. These script files encapsulate the standard flags, making it easier for developers to run the project.
