# Setup Notes

## System Requirements
- Operating System: Linux (Ubuntu 20.04+ recommended) or Windows 10/11
- Processor: Minimum 4 cores, 8+ recommended
- Memory: 8GB RAM minimum, 16GB+ recommended
- Storage: 10GB available space for installation and temporary files
- No internet connection required after initial setup (air-gapped)

## Installation

### 1. Environment Preparation
```bash
# Create a dedicated user for the assurance system (recommended)
sudo useradd -m -s /bin/bash assurance
sudo passwd assurance

# Switch to the assurance user
su - assurance

# Create installation directory
mkdir -p ~/assurance-system
cd ~/assurance-system
```

### 2. Dependency Installation (Online Phase)
*This step requires internet access to download dependencies*

```bash
# Clone the repository (if not already done)
git clone <repository-url> .
# OR copy the source code via secure external media

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies from requirements.txt
pip install --no-cache-dir -r requirements.txt

# Download any required ML model data (if applicable)
python -c "import nltk; nltk.download('punkt')"  # Example for NLTK data
```

### 3. Air-Gapped Transfer Preparation
```bash
# Create installation package for air-gapped transfer
cd ..
tar -czvf assurance-system-airgap.tar.gz assurance-system/

# Transfer the archive to the air-gapped environment via secure means
# (encrypted USB drive, secure file transfer, etc.)
```

### 4. Installation in Air-Gapped Environment
```bash
# On the air-gapped system:
tar -xzvf assurance-system-airgap.tar.gz
cd assurance-system
source venv/bin/activate

# Verify installation
python -c "import assurance; print('Assurance system imported successfully')"
```

## Configuration

### 1. Environment Variables
Create a `.env` file in the root directory:
```bash
# Analysis settings
ASSURANCE_MAX_FILE_SIZE_MB=100
ASSURANCE_TIMEOUT_SECONDS=300
ASSURANCE_CONFIDENCE_THRESHOLD=0.7

# Paths (adjust as needed)
ASSURANCE_RULES_DIR=./rules
ASSURANCE_MODELS_DIR=./models
ASSURANCE_CACHE_DIR=./cache
ASSURANCE_LOG_DIR=./logs
```

### 2. Rule and Model Configuration
- Place custom analysis rules in `./rules/` directory
- Place pre-trained ML models in `./models/` directory
- Rule format: YAML or JSON (see examples in `rules/examples/`)

### 3. Logging Configuration
Edit `logging.conf` to adjust log levels and output formats:
```ini
[loggers]
keys=root,assurance

[logger_assurance]
level=INFO
handlers=console,file
qualname=assurance
propagate=0

[handlers]
keys=console,file

[handler_console]
class=StreamHandler
level=INFO
formatter=simple
args=(sys.stdout,)

[handler_file]
class=FileHandler
level=DEBUG
formatter=detailed
args=('logs/assurance.log',)

[formatters]
keys=simple,detailed
```

## Running the System

### Basic Usage
```bash
# Activate virtual environment
source venv/bin/activate

# Run assurance analysis on a target directory
python -m assurance.cli --target /path/to/target --output ./reports

# With additional options
python -m assurance.cli --target /path/to/target --output ./reports \
    --format json --confidence-threshold 0.8 --max-workers 4
```

### Command Line Options
```
--target PATH          : Directory or file to analyze (required)
--output PATH          : Output directory for reports (default: ./reports)
--format FORMAT        : Report format (json, html, txt) (default: json)
--confidence-threshold FLOAT : Minimum confidence for findings (0.0-1.0) (default: 0.7)
--max-workers INT      : Number of parallel workers (default: CPU count)
--timeout SECONDS      : Analysis timeout per file (default: 300)
--rules-dir PATH       : Custom rules directory (default: ./rules)
--log-level LEVEL      : Logging level (DEBUG, INFO, WARNING, ERROR) (default: INFO)
```

## Verification in Air-Gapped Environment

### 1. Integrity Check
```bash
# Verify installation integrity
python -m assurance.verify --check-all

# Verify dependencies
pip check
```

### 2. Test Run
```bash
# Run on sample data (if included)
python -m assurance.cli --target ./sample-data --output ./test-output

# Verify output was generated
ls -la ./test-output/
```

## Troubleshooting

### Common Issues
1. **Dependency Conflicts**: Ensure using the exact versions in requirements.txt
2. **Permission Errors**: Run with appropriate user privileges for file access
3. **Memory Issues**: Reduce --max-workers or increase system RAM
4. **Model Loading Failures**: Verify ML model files are present and not corrupted

### Logs Location
- Main log: `logs/assurance.log`
- Error log: `logs/assurance_error.log`
- Audit log: `logs/audit.jsonl` (JSON Lines format)

## Maintenance
- Regularly update the `.env` file as needed
- Monitor log files for unusual activity
- Backup the `rules/` and `models/` directories periodically
- Re-run integrity checks after any modifications