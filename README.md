# Nessus TLS Parser
# Nessus TLS/SSL and Certificte Security Finding and Host/Port Parser

Parses TLS/SSL and Certificate Security findings and affected hosts/ports from .Nessus (XML) files. 

A quick fix to make life simple and extract specified findings related to TLS/SSL and Certificates and presents them in an easily readable format. The tool supports output in both Markdown and plain text formats.

## Prerequisites
- Python 3.x
- Nessus scan file in .nessus (XML) format

## Installation
Clone the repository to your local machine:

```bash
git clone https://github.com/smhuda/nessus-tls-parser.git
```
## Usage
Navigate to the script directory and run the script with Python:

```normal
python nessus_file_parser.py -i [input_file.nessus] -o [output_file] -f [format]

-i: Path to the input .nessus file.
-o: Path for the output file.
-f: Output format (markdown or text).
```
## Contributing
Contributions, issues, and feature requests are welcome! 

If you liked this or it helped you in anyway

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/smhuda)
