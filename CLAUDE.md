# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PyAntiSpam is a Python-based anti-spam detection and filtering library. This is currently an empty repository that will likely develop into a comprehensive spam detection system.

## Development Setup

This appears to be a new Python project. Common setup will likely involve:

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies (once requirements.txt or pyproject.toml exists)
pip install -r requirements.txt
# or
pip install -e .
```

## Common Commands

### Development Setup
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install in development mode
pip install -e .
```

### PyAntiSpam Commands
```bash
# Initial setup
pyantispam setup

# Test configuration
pyantispam test-config

# Run spam detection
pyantispam run
pyantispam run --dry-run

# Daemon mode
pyantispam daemon

# List management
pyantispam whitelist add email@domain.com
pyantispam blacklist add spam-domain.com
pyantispam whitelist list
pyantispam blacklist list

# Status and logs
pyantispam status
pyantispam logs --days 7
```

### Development Commands
```bash
# Run tests (when implemented)
python -m pytest

# Code formatting
black src/

# Linting
flake8 src/
pylint src/

# Type checking
mypy src/
```

## Project Architecture

PyAntiSpam is structured as a modular anti-spam system:

### Core Components
- **CLI Interface** (`src/pyantispam/cli.py`): Main command-line interface
- **Configuration** (`src/pyantispam/config/`): YAML config + environment variables
- **Email Client** (`src/pyantispam/email/`): IMAP operations and email processing
- **List Management** (`src/pyantispam/filters/`): Whitelist/blacklist operations
- **ML Module** (`src/pyantispam/ml/`): Machine learning models (to be implemented)
- **LLM Integration** (`src/pyantispam/llm/`): Large language model integration (to be implemented)

### Detection Pipeline
1. **Static Filters**: Whitelist/blacklist checking (highest priority)
2. **ML Classification**: Local model for fast detection
3. **LLM Analysis**: For uncertain cases requiring contextual understanding
4. **Action Execution**: Move spam to designated folder with logging

### Configuration Files
- `config.yaml`: Main configuration (email accounts, detection settings, actions)
- `.env`: Credentials and API keys (never commit to git)
- `data/whitelist.json` & `data/blacklist.json`: Persistent filter lists

## Development Guidelines

- Follow PEP 8 style guidelines for Python code
- Use type hints for better code documentation and IDE support
- Implement comprehensive testing for spam detection accuracy
- Consider privacy and security implications when handling user content
- Document API endpoints and model performance metrics