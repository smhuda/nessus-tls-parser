import xml.etree.ElementTree as ET
import argparse
from collections import defaultdict

def parse_nessus_file(filename, findings):
    results = defaultdict(lambda: defaultdict(set))

    tree = ET.parse(filename)
    root = tree.getroot()

    for block in root.findall('./Report/ReportHost'):
        host = block.get('name')
        for item in block.findall('./ReportItem'):
            plugin_id = item.get('pluginID')
            if plugin_id in findings:
                port = item.get('port')
                results[plugin_id][host].add(port)

    return results

def write_markdown(file, findings, results):
    for plugin_id, hosts in results.items():
        file.write(f"## {findings[plugin_id]}\n\n")  # Markdown header
        file.write("| IP Address | Ports |\n")
        file.write("|-------------|-------|\n")  # Header separator
        for host, ports in hosts.items():
            ports_str = ', '.join(sorted(ports))
            file.write(f"| {host} | {ports_str} |\n")
        file.write("\n")

def write_text(file, findings, results):
    for plugin_id, hosts in results.items():
        file.write(f"{findings[plugin_id]}\n")
        for host, ports in hosts.items():
            ports_str = ', '.join(sorted(ports))
            file.write(f"{host} ({ports_str})\n")
        file.write("\n")

def main():
    # Define the findings
    findings = {
        "104743": "TLS 1.0",
        "157288": "TLS 1.1",
        "20007": "SSL 2/3",
        "31705": "Anonymous Ciphers",
        "42873": "Medium Strength/SWEET32",
        "65821": "RC4/bar mitzvah",
        "26928": "Weak Cipher Suites",
        "69551": "RSA Keys Less Than 2048 Bits",
        "35291": "Certificate signed with weak hashing algo",
        "83875": "Diffie-helman less than 1024 bits (logjam)",
        "81606": "EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)",
        "78479": "SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)",
        "51192": "SSL Certificate Cannot Be Trusted",
        "57582": "Self Signed Certificate",
        "45411": "Certificate with wrong hostname",
        "56284": "SSL Certificate Fails to Adhere to Basic Constraints / Key Usage Extensions",
        "83738": "SSL/TLS EXPORT_DHE <= 512-bit Export Cipher Suites Supported (Logjam)",
        "15901": "Expired certificates",
        "42880": "TLS Renegotiation Handshakes MiTM Plaintext Data Injection"
    }

    parser = argparse.ArgumentParser(description="Nessus File Parser")
    parser.add_argument("-i", "--input", help="Input .nessus file", required=True)
    parser.add_argument("-o", "--output", help="Output text file", required=True)
    parser.add_argument("-f", "--format", choices=['markdown', 'text'], default='text', help="Output format")
    args = parser.parse_args()

    results = parse_nessus_file(args.input, findings)

    with open(args.output, 'w') as file:
        if args.format == 'markdown':
            write_markdown(file, findings, results)
        else:
            write_text(file, findings, results)

if __name__ == "__main__":
    main()
