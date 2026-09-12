import socket, struct, json, time
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', 5500))
srv.listen(16)
print("Listening on 5500...")
while True:
    conn, addr = srv.accept()
    length_b = b""
    while len(length_b) < 4:
        length_b += conn.recv(4 - len(length_b))
    length = struct.unpack('>I', length_b)[0]
    raw = b""
    while len(raw) < length:
        raw += conn.recv(length - len(raw))
    conn.close()
    try:
        j = json.loads(raw.decode('utf-8', errors='ignore').split('}')[0] + '}')
        print(f"Received seq {j.get('seq')} from {j.get('branch_id')}")
    except Exception as e:
        print("Raw:", raw[:50], e)
