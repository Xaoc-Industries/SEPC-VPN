from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from concurrent.futures import ThreadPoolExecutor
import oqs
import re
import base64
import requests
import json
import argparse
import os
import hashlib
import time
import secrets
import sys
import socket
import math
import fcntl
import struct
import threading

TUN_PATH = "/dev/net/tun"
IFACE_NAME = "sepc0"
BUF_SIZE = 1400
NONCE_LEN = 12
SEQ_MAGIC = b"SP"
VER = 1
HEADER_LEN = 25
FRAME_STRUCT = "<Q I"
CTRL_FLAG = 0x01
FRAG_FLAG = 0x02
FRAG_EXT_LEN = 12
MAX_CHUNK = 1000

def set_tun_mtu(iface, mtu):
    SIOCSIFMTU = 0x8922
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifr = struct.pack('16sH14s', iface.encode(), mtu, b'\x00' * 14)
    fcntl.ioctl(s, SIOCSIFMTU, ifr)
    s.close()

class SharedState:
    def __init__(self, pool_ttl, pool_json, pool_index_list):
        self.pool_ttl = pool_ttl
        self.pool_json = pool_json
        self.pool_index_list = pool_index_list
        self.lock = threading.Lock()

def listen(port_number):
    host = '0.0.0.0'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port_number))
        server_socket.listen(1)
        print(f"Waiting for peer...")
        conn, addr = server_socket.accept()
        with conn:
            data = conn.recv(1)
            if data == bytes([255]):
                print(f"Received communication request from {addr[0]}")
                server_socket.close()
                return addr[0]

def post_pool(url, b64_encrypted_pool):
    try:
        resp = requests.put(url, json={"data": b64_encrypted_pool}, timeout=20)
    except Exception as e:
        raise SystemExit(f"Encode failed: pool vault unreachable: {e}")
    if resp.status_code != 200:
        raise SystemExit(f"Encode failed: pool upload status {resp.status_code}")

def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SystemExit("Connection closed")
        buf.extend(chunk)
    return bytes(buf)

def derive_keys(raw_shared: bytes, salt: bytes):
    def hk(info: bytes, ln: int):
        return HKDF(algorithm=hashes.SHA256(), length=ln, salt=salt, info=info).derive(raw_shared)
    return (
        hk(b"SEPC filetool handshake v1", 32),
        hk(b"SEPC filetool data channel v1", 32),
        hk(b"SEPC filetool pool SIV v1", 64),
    )

def getkey_kyber(port_number, endpoint_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(20)
        attempt = 0
        while attempt < 5:
            try:
                s.connect((endpoint_ip, port_number))
                break
            except:
                attempt += 1
                time.sleep(2)
        else:
            raise SystemExit("Failed to connect to peer for key exchange.")
        pk_len = struct.unpack("<I", recv_exact(s, 4))[0]
        server_pk = recv_exact(s, pk_len)
        with oqs.KeyEncapsulation("Kyber1024") as kem:
            ct, raw_shared = kem.encap_secret(server_pk)
        s.sendall(struct.pack("<I", len(ct)))
        s.sendall(ct)
        head = recv_exact(s, 16 + NONCE_LEN)
        salt, nonce = head[:16], head[16:]
        clen = struct.unpack("<I", recv_exact(s, 4))[0]
        ct_meta = recv_exact(s, clen)
        handshake_key, data_key, siv_key = derive_keys(raw_shared, salt)
        meta_bytes = ChaCha20Poly1305(handshake_key).decrypt(nonce, ct_meta, b"")
        meta = json.loads(meta_bytes.decode("utf-8"))
        file_sha_hex = meta.get("file_sha", "0" * 64)
        aad_bytes = base64.b64decode(meta["aad_b64"].encode("ascii"))
        pool_id = int(meta["pool_id"])
        return {
            "handshake_key": handshake_key,
            "data_key": data_key,
            "siv_key": siv_key,
            "aad_bytes": aad_bytes,
            "pool_id": pool_id,
            "file_sha_hex": file_sha_hex
        }


def sendkey_kyber(port_number, meta_fields):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(20)
        try:
            s.bind(('0.0.0.0', port_number))
        except:
            raise SystemExit("Failed to bind to port for key exchange.")
        s.listen(1)
        conn, addr = s.accept()
        conn.settimeout(20)
        with conn, oqs.KeyEncapsulation("Kyber1024") as kem:
            public_key = kem.generate_keypair()
            conn.sendall(struct.pack("<I", len(public_key)))
            conn.sendall(public_key)
            ct_len = struct.unpack("<I", recv_exact(conn, 4))[0]
            ct = recv_exact(conn, ct_len)
            raw_shared = kem.decap_secret(ct)
            salt = os.urandom(16)
            handshake_key, data_key, siv_key = derive_keys(raw_shared, salt)
            aad_bytes = os.urandom(16)
            meta = {
                "pool_id": int(meta_fields["pool_id"]),
                "aad_b64": base64.b64encode(aad_bytes).decode("ascii")
            }
            meta_bytes = json.dumps(meta).encode("utf-8")
            aead = ChaCha20Poly1305(handshake_key)
            nonce = os.urandom(NONCE_LEN)
            ct_meta = aead.encrypt(nonce, meta_bytes, b"")
            conn.sendall(salt + nonce + struct.pack("<I", len(ct_meta)) + ct_meta)
            return {
                "handshake_key": handshake_key,
                "data_key": data_key,
                "siv_key": siv_key,
                "aad_bytes": aad_bytes
            }
        return {"handshake_key": handshake_key, "data_key": data_key, "siv_key": siv_key, "aad_bytes": aad_bytes}

def make_pool_plain(timeout):
    poolbytedata = []
    all_bytes = list(range(256))
    for _ in range(30):
        _sr.shuffle(all_bytes)
        poolbytedata += all_bytes
    pooldata_b64 = base64.b64encode(bytes(poolbytedata)).decode("ascii")
    pool_hash_hex = hashlib.sha256(pooldata_b64.encode("ascii")).hexdigest()
    genat = int(time.time())
    expat = genat + timeout
    pool_id = _sr._randbelow(999_999_999) + 1
    poolidhash = hashlib.sha256(str(pool_id).encode("ascii")).hexdigest()
    pool_json = {
        "pool_id": str(pool_id),
        "TTL": expat,
        "GeneratedAt": genat,
        "EnSrc": "V2.0",
        "SHA256": pool_hash_hex,
        "Data": pooldata_b64,
    }
    pool_json_str = json.dumps(pool_json, separators=(",", ":"))
    return pool_json_str, pool_id, pool_hash_hex, poolidhash

def encrypt_pool_for_vault(pool_json_str: str, siv_key: bytes, aad_bytes: bytes) -> str:
    out_bytes = pool_json_str.encode("utf-8")
    if isinstance(aad_bytes, bytearray):
        aad_bytes = bytes(aad_bytes)
    ciphertext = aessiv_encrypt(siv_key, aad_bytes, out_bytes)
    return base64.b64encode(ciphertext).decode("ascii")

def digester(current_pool):
    required_bytes = list(range(256))
    entropy_pool = json.loads(current_pool)
    entropy_pool_bytes = base64.b64decode(entropy_pool["Data"])
    pool_index_list = {}
    for byt in required_bytes:
        matches = [i for i, byte in enumerate(entropy_pool_bytes) if byte == byt]
        pool_index_list[byt] = matches
    return pool_index_list

def reference_mapper(pool_index_list, raw_bytes):
    host_payload_index_map = []
    for byt in raw_bytes:
        indexes = pool_index_list.get(byt)
        this_selection = secrets.choice(indexes)
        host_payload_index_map.append(this_selection)
    pld_arr = [i.to_bytes(2, 'big') for i in host_payload_index_map]
    pld = b''.join(pld_arr)
    return pld

def decoder(indices, current_pool):
    entropy_pool = json.loads(current_pool)
    entropy_pool_bytes = base64.b64decode(entropy_pool["Data"])
    pool_hash = entropy_pool["SHA256"]
    calculated_hash = hashlib.sha256()
    calculated_hash.update(entropy_pool["Data"].encode('ascii'))
    calc_pool_hash = calculated_hash.hexdigest()
    if calc_pool_hash != pool_hash:
        raise SystemExit("Decode Failed: Pool corruption detected.")
    payload_arr = bytearray()
    for index in indices:
        payload_arr.append(entropy_pool_bytes[index])
    decoded = bytes(payload_arr)
    return decoded

def aessiv_encrypt(key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    siv = AESSIV(key)
    try:
        return siv.encrypt([aad], plaintext)
    except TypeError:
        return siv.encrypt(plaintext, [aad])

def aessiv_decrypt(key: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    siv = AESSIV(key)
    try:
        return siv.decrypt([aad], ciphertext)
    except TypeError:
        return siv.decrypt(ciphertext, [aad])

def create_tun():
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000
    tun = os.open(TUN_PATH, os.O_RDWR)
    ifr = struct.pack('16sH14s', IFACE_NAME.encode(), IFF_TUN | IFF_NO_PI, b'\x00' * 14)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    print(f"[+] Opened TUN device: {IFACE_NAME}")
    return tun

def reader(tun, sock, shared, aead, aad_base, timeout, peer_ip, port, poolauth):
    seq = 0
    while True:
        data = os.read(tun, BUF_SIZE)
        if not data:
            continue
        try:
            with shared.lock:
                ttl_now = shared.pool_ttl
                curr_map = shared.pool_index_list
                new_pool_json = shared.pool_json
            if ttl_now <= int(time.time()) and poolauth:
                print("Initiating Pool change...")
                new_pool_json, new_pool_id, new_poolhash, new_poolidhash = make_pool_plain(timeout)
                new_pool_ttl = json.loads(new_pool_json)["TTL"]
                new_pool_index_list = digester(new_pool_json)
                payload = bytes([0xFF]) + new_pool_json.encode("utf-8")
                indices = reference_mapper(curr_map, payload)
                nonce = struct.pack("<Q", seq) + os.urandom(NONCE_LEN - 8)
                aad = aad_base + struct.pack("<Q", seq)
                ct = aead.encrypt(nonce, indices, aad)
                frag_id = secrets.randbits(32)
                total = len(ct)
                frag_cnt = (total + MAX_CHUNK - 1) // MAX_CHUNK
                offset = 0
                frag_idx = 0
                while offset < total:
                    chunk = ct[offset: offset + MAX_CHUNK]
                    offset += len(chunk)
                    header = bytearray()
                    flags = CTRL_FLAG | (FRAG_FLAG if frag_cnt > 1 else 0)
                    header += bytes([flags])
                    header += struct.pack("<Q", seq)
                    header += struct.pack("<I", len(chunk))
                    header += nonce
                    if frag_cnt > 1:
                        header += struct.pack("<I", total)
                        header += struct.pack("<I", frag_id)
                        header += struct.pack("<H", frag_idx)
                        header += struct.pack("<H", frag_cnt)
                    sock.send(header + chunk)
                    frag_idx += 1
                with shared.lock:
                    shared.pool_index_list = new_pool_index_list
                    shared.pool_json = new_pool_json
                    shared.pool_ttl = new_pool_ttl
                    seq = (seq + 1) & 0xFFFFFFFFFFFFFFFF
            else:
                with shared.lock:
                    curr_map = shared.pool_index_list
                indices = reference_mapper(curr_map, data)
                nonce = struct.pack("<Q", seq) + os.urandom(NONCE_LEN - 8)
                aad = aad_base + struct.pack("<Q", seq)
                ct = aead.encrypt(nonce, indices, aad)
                header = bytearray()
                header += bytes([0])
                header += struct.pack("<Q", seq)
                header += struct.pack("<I", len(ct))
                header += nonce
                sock.send(header + ct)
                seq = (seq + 1) & 0xFFFFFFFFFFFFFFFF
        except Exception as e:
            print(f"[!] Send error: {e}")
            break

def writer(tun, sock, shared, aead, aad_base, poolauth, pool_ttl_current, retry):
    buf = b""
    reassembly = {}
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                print("[!] socket closed by peer")
                break
            buf += chunk
            while True:
                if len(buf) < HEADER_LEN:
                    break
                flags = buf[0]
                seq, chunk_len = struct.unpack("<Q I", buf[1:1+12])
                nonce = buf[13:25]
                pos = HEADER_LEN
                if flags & FRAG_FLAG:
                    if len(buf) < HEADER_LEN + FRAG_EXT_LEN:
                        break
                    total_ct_len, frag_id = struct.unpack("<I I", buf[pos:pos+8])
                    frag_idx, frag_cnt = struct.unpack("<H H", buf[pos+8:pos+12])
                    pos += FRAG_EXT_LEN
                else:
                    total_ct_len = chunk_len
                    frag_id = 0
                    frag_idx = 0
                    frag_cnt = 1
                total_len = pos + chunk_len
                if len(buf) < total_len:
                    break
                chunk = buf[pos:total_len]
                buf = buf[total_len:]
                if frag_cnt == 1:
                    ct = chunk
                else:
                    key = (seq, frag_id)
                    entry = reassembly.get(key)
                    if not entry:
                        entry = {"total": total_ct_len, "parts": [None] * frag_cnt, "have": 0, "nonce": nonce}
                        reassembly[key] = entry
                    if entry["nonce"] != nonce:
                        print(f"[!] Nonce changed mid reassembly for seq={seq}")
                        reassembly.pop(key, None)
                        continue
                    if 0 <= frag_idx < frag_cnt and entry["parts"][frag_idx] is None:
                        entry["parts"][frag_idx] = chunk
                        entry["have"] += 1
                    if entry["have"] < frag_cnt:
                        continue
                    ct = b"".join(entry["parts"])
                    reassembly.pop(key, None)
                try:
                    aad = aad_base + struct.pack("<Q", seq)
                    indices_blob = aead.decrypt(nonce, ct, aad)
                except Exception as e:
                    print(f"[!] Decrypt failed for seq={seq}: {e}")
                    continue
                try:
                    if len(indices_blob) % 2 != 0:
                        print("[!] Bad encoded length, skipping frame")
                        continue
                    indices = [int.from_bytes(indices_blob[i:i+2], "big")
                                       for i in range(0, len(indices_blob), 2)]
                    with shared.lock:
                        pj_snapshot = shared.pool_json
                    decoded = decoder(indices, pj_snapshot)
                except Exception as e:
                    print(f"[!] Decode failed for seq={seq}: {e}")
                    continue
                if not decoded or len(decoded) < 20:
                    print(f"[!] Skipping invalid decoded packet (len={len(decoded) if decoded else 0})")
                    continue
                if decoded[0] == 255 and not poolauth:
                    print("Accepting Pool change...")
                    try:
                         pj = decoded[1:].decode("utf-8")
                         obj = json.loads(pj)
                         calc = hashlib.sha256(obj["Data"].encode("ascii")).hexdigest()
                         if calc != obj["SHA256"]:
                             print("[!] Rejected pool change due to hash mismatch")
                             continue
                         new_map = digester(pj)
                         pool_ttl_current = int(obj["TTL"]) + 30
                         with shared.lock:
                             shared.pool_json = pj
                             shared.pool_ttl = int(obj["TTL"]) + 30
                             shared.pool_index_list = new_map
                    except Exception as e:
                        print(f"[!] Failed to accept pool change: {e}")
                        continue
                else:
                    if pool_ttl_current <= int(time.time()) and not poolauth:
                        print("[!] Entropy pool de-synch detected, dropping to reinitialization.")
                        return False
                if decoded[0] != 0x45:
                    print(f"[!] Skipping non-IPv4 packet (first byte: {decoded[0]:02x})")
                    continue
                try:
                    os.write(tun, decoded)
                except OSError as e:
                    print(f"[!] os.write() failed: {e} (len={len(decoded)})")
                    continue
        except Exception as e:
            if retry:
                return False
            else:
                raise SystemExit(f"[!] Receive error: {e}")

def server_mode(tun, port, pool_index_list, pool_json, data_key, aad_bytes, pool_id, pool_ttl, timeout, peer_ip, retry):
    aead = ChaCha20Poly1305(data_key)
    aad_base = aad_bytes + struct.pack("<I", int(pool_id))
    shared = SharedState(pool_ttl, pool_json, pool_index_list)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", port))
        print(f"[+] Listening on port {port}...")
        data, addr = s.recvfrom(4096)
        print(f"[+] Connect from {addr[0]}:{addr[1]}")
        s.connect(addr)
        t1 = threading.Thread(target=reader, args=(tun, s, shared, aead, aad_base, timeout, None, None, True), daemon=True)
        t2 = threading.Thread(target=writer, args=(tun, s, shared, aead, aad_base, True, pool_ttl, retry), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()

def client_mode(tun, peer_ip, port, pool_index_list, pool_json, data_key, aad_bytes, pool_id, pool_ttl, timeout, retry):
    aead = ChaCha20Poly1305(data_key)
    aad_base = aad_bytes + struct.pack("<I", int(pool_id))
    shared = SharedState(pool_ttl, pool_json, pool_index_list)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((peer_ip, port))
        print(f"[+] Connecting to {peer_ip}:{port}...")
        s.send(b"\xff")
        print("[+] Connected.")
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_reader = executor.submit(reader, tun, s, shared, aead, aad_base, timeout, None, None, False)
            future_writer = executor.submit(writer, tun, s, shared, aead, aad_base, False, pool_ttl, retry)
            result = future_writer.result()
            if result is False and retry:
                return True
            future_reader.cancel()
        
def main():
    parser = argparse.ArgumentParser(description="Obfuscated TUN Tunnel with Encode/Decode")
    parser.add_argument("-c", "--connect", help="peer IP or DNS")
    parser.add_argument("-l", "--listen", action="store_true")
    parser.add_argument("-p", "--pool", help="Pool vault to use.")
    parser.add_argument("-t", "--timeout", help="Timeout for pools.")
    parser.add_argument("-r", "--reconnect", action="store_true")
    parser.add_argument("-kp", "--keyport", help="Port to use for key exchange.")
    parser.add_argument("-dp", "--dataport", help="Port to use for data exchange.")
    args = parser.parse_args()
    if args.keyport:
        key_port = int(args.keyport)
    else:
        key_port = 6767
    if args.dataport:
        data_port = int(args.dataport)
    else:
        data_port = 6969
    if args.timeout:
        timeout = int(args.timeout)
    else:
        timeout = 600
    tun = create_tun()
    set_tun_mtu(IFACE_NAME, 1500)
    if args.pool:
        pool_url = args.pool
    else:
        pool_url = "https://www.hekateforge.com:8080/pool"
    if args.reconnect:
        retry = True
    else:
        retry = False
    if args.connect:
        ent_pool, pool_id, poolhash, poolidhash = make_pool_plain(timeout)
        pool_ttl = json.loads(ent_pool)["TTL"]
        vault_id = f"{pool_url}/{poolidhash}"
        try:
            with socket.create_connection((args.connect, data_port), timeout=5) as probe:
                probe.sendall(bytes([255]))
        except Exception as e:
            raise SystemExit(f"Failed to probe data port on receiver: {e}")
        hk = sendkey_kyber(key_port, {"pool_id": pool_id})
        siv_key = hk["siv_key"]
        aad_bytes = hk["aad_bytes"]
        data_key = hk["data_key"]
        enc_pool_b64 = encrypt_pool_for_vault(ent_pool, siv_key, aad_bytes)
        pool_references = digester(ent_pool)
        post_pool(vault_id, enc_pool_b64)
        server_mode(tun, data_port, pool_references, ent_pool, data_key, aad_bytes, pool_id, pool_ttl, timeout, args.connect, False)
    else:
        retry_now = True
        while retry_now:
            retry_now = False
            currentpeer = listen(data_port)
            hk = getkey_kyber(key_port, currentpeer)
            data_key = hk["data_key"]
            siv_key = hk["siv_key"]
            aad_bytes = hk["aad_bytes"]
            pool_id = hk["pool_id"]
            poolidhash = hashlib.sha256(str(pool_id).encode("ascii")).hexdigest()
            vault_id = f"{pool_url}/{poolidhash}"
            try:
                time.sleep(2)
                resp = requests.get(vault_id, timeout=20)
                if resp.status_code != 200:
                    raise SystemExit("Failed to retrieve pool.")
                pool_data = resp.json()
                if pool_data.get("data") == "X":
                    raise SystemExit("Pool unavailable.")
            except Exception as e:
                raise SystemExit(f"No valid pool response: {e}")
            expected_sha_hex = hk["file_sha_hex"]
            enc_pool = base64.b64decode(pool_data["data"])
            pool_json = aessiv_decrypt(siv_key, aad_bytes, enc_pool).decode("utf-8")
            pool_hash = json.loads(pool_json)["SHA256"]
            pool_ttl = int(json.loads(pool_json)["TTL"]) + 30
            timeout = pool_ttl - int(json.loads(pool_json)["GeneratedAt"])
            if hashlib.sha256(json.loads(pool_json)["Data"].encode("ascii")).hexdigest() != pool_hash:
                raise SystemExit("Pool corruption detected before use")
            b64_pool = json.loads(pool_json)["Data"]
            pool_bytes = base64.b64decode(b64_pool)
            pool_references = digester(pool_json)
            retry_now = client_mode(tun, currentpeer, data_port, pool_references, pool_json, data_key, aad_bytes, pool_id, pool_ttl, timeout, retry)

if __name__ == "__main__":
    print("--------------------------------------------------------------------------------")
    print("|     HekateForge SEPC VPN Protocol Release 2.0 - Patent Pending #3278624      |")
    print("--------------------------------------------------------------------------------")
    _sr = secrets.SystemRandom()
    main()
