# Password Checker

A command-line tool for checking password security and strength. This tool helps you verify if your passwords have been compromised in data breaches and assess their overall strength.

## Features

- Check if passwords have been exposed in known data breaches
- Analyze password strength based on various security criteria
- Process multiple passwords from CSV files
- Command-line interface for easy integration into workflows

## Installation

- Clone the repository
```bash
    git clone https://github.com/theholyjack/password-checker.git
```
- Install locally using pip
```bash
    cd password-checker
    pip install .  
```




## Usage

The tool can be used directly from the command line:

```bash
password-checker [options]
```

### Check Single Password

To check a single password's security and strength:

```bash
password-checker --input "your_password"
password-checker -i "your_password"
```

### Process CSV File

To check multiple passwords from a CSV file:

```bash
password-checker -c path/to/your/csv
password-checker --csv path/to/your/csv
```

## Requirements

- Python 3.x
- requests
- colorama

## Development

To set up the development environment:

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -e .
   ```

## License

Do what you please. 

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security Note

This tool uses secure methods to check passwords against known breaches without transmitting your actual passwords. It implements the k-anonymity model for secure password verification.