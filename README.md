# veracode-policy-results-to-pipeline-json

A small plugin that converts Veracode policy scan results into the equivalent pipeline scan output (for usage with Veracode Fix).

## Purpose

This tool reads Veracode policy result data and transforms it into a JSON structure suitable for use with Veracode Fix.

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Install dependencies (see Installation section above)
2. Run the plugin (it will prompt you for input)

## Output

A results.json file which can be used with the veracode fix CLI:
```bash
veracode fix "./<file_or_directory_to_fix>" --results ./results.json --type <directory_or_fil> --apply
```