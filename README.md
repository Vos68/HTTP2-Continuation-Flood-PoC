# PoC HTTP/2 Continuation Flood DOS Attack

This script serves the purpose of assessing the HTTP version supported by a list of target IP addresses or domain names and potentially executing a Denial of Service (DOS) attack on servers that support HTTP/2. The script is capable of handling large lists of targets asynchronously.

It operates under the assumption that if a server accepts a significant number of packets with abnormal headers, it could potentially be vulnerable to a DOS attack.

For more detailed information about the vulnerability being exploited, refer to this KB article - https://kb.cert.org/vuls/id/421644. Additionally, a broader explanation of the vulnerability can be found here - https://nowotarski.info/http2-continuation-flood-technical-details. These resources provide technical insights into the vulnerability and its implications.

# Affected CVEs
    CVE-2024-27983
    CVE-2024-27919
    CVE-2024-2758
    CVE-2024-2653
    CVE-2023-45288
    CVE-2024-28182
    CVE-2024-27316
    CVE-2024-31309
    CVE-2024-30255

# Features

    HTTP Version Checking: The script checks the HTTP version supported by each target in the provided list. It assesses whether the target supports HTTP/2, SPDY/3, or HTTP/1.1 protocols.

    DOS Attack: For targets supporting HTTP/2, the script attempts to execute a DOS attack by flooding the server with packets containing large and abnormal headers. In desire to avoid real DoS script gently waits for the server's acceptance of 150 packets with abnormal headers, assuming potential vulnerability based on this observation.

    Logging: The script logs the results of HTTP version checks and any encountered errors to a log file for further analysis.

## Usage

1. Install the required dependencies:

```bash
pip install -r requirements.txt
```
2. Run the script with the following command:
```
python3.9 main.py <filename>
```
Replace <filename> with the path to the file containing IP addresses or domain names (one per line) to be checked.

# Additional Notes
- The script will log the results of the HTTP version checks and any errors encountered during execution in the http_version_check.log file.
- The USER_AGENT constant can be customized to specify the User-Agent header for HTTP requests.
- The LARGE_HEADER_VALUE constant defines the value for a large header used in the DOS attack.

# Disclaimer
This script is provided for educational and informational purposes only. Use it responsibly and do not perform any unauthorized actions or attacks on networks or systems without proper authorization.