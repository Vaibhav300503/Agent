# SOC Platform Server

This directory contains the server-side components of the SOC Platform.

## Installation

To install the server, run the automated installation script:
```bash
sudo ./install.sh
```

For detailed instructions and features, please refer to the documentation in the root of the project:
- `docs/INSTALLATION.md`
- `docs/FEATURES.md`
- `docs/WORKING.md`

## Components
- `api/`: REST API for log ingestion.
- `workers/`: Background workers for parsing, enrichment, and detection.
- `main.py`: Main orchestrator.
- `install.sh`: Automated installer for Ubuntu/Debian.
